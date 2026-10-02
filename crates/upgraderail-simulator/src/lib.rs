use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};
use tokio::{process::Command, time::timeout};
use upgraderail_core::{Finding, Severity};
use url::Url;

mod scenario;

pub use scenario::{AuthorizationMode, ScenarioExpectations, ScenarioNetwork, SimulationScenario};

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("Stellar CLI is unavailable: {0}")]
    Cli(String),
    #[error("Stellar CLI command failed: {0}")]
    CliCommand(String),
    #[error("unsupported Stellar CLI version `{0}`; version 28.x is required")]
    CliVersion(String),
    #[error("RPC URL is invalid: {0}")]
    Url(String),
    #[error("RPC request failed: {0}")]
    Rpc(String),
    #[error("RPC returned error: {0}")]
    JsonRpc(String),
    #[error("RPC response is malformed: {0}")]
    Malformed(String),
    #[error("operation timed out")]
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractInvocation {
    pub contract_id: String,
    pub source_account: String,
    pub rpc_url: String,
    pub network_passphrase: String,
    pub function: String,
    pub args: BTreeMap<String, String>,
    pub authorization_mode: AuthorizationMode,
}

#[derive(Clone, Debug)]
pub struct StellarCli {
    program: PathBuf,
}

impl Default for StellarCli {
    fn default() -> Self {
        Self {
            program: PathBuf::from("stellar"),
        }
    }
}

impl StellarCli {
    #[must_use]
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    #[must_use]
    pub fn build_args(invocation: &ContractInvocation) -> Vec<String> {
        let mut args = vec![
            "contract".into(),
            "invoke".into(),
            "--build-only".into(),
            "--send".into(),
            "no".into(),
            "--contract-id".into(),
            invocation.contract_id.clone(),
            "--source-account".into(),
            invocation.source_account.clone(),
            "--rpc-url".into(),
            invocation.rpc_url.clone(),
            "--network-passphrase".into(),
            invocation.network_passphrase.clone(),
            "--auth-mode".into(),
            invocation.authorization_mode.stellar_cli_value().into(),
            "--".into(),
            invocation.function.clone(),
        ];
        for (name, value) in &invocation.args {
            args.push(format!("--{name}"));
            args.push(value.clone());
        }
        args
    }

    pub async fn build_transaction(
        &self,
        invocation: &ContractInvocation,
    ) -> Result<String, SimulationError> {
        let output = Command::new(&self.program)
            .args(Self::build_args(invocation))
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|error| SimulationError::Cli(error.to_string()))?;
        if !output.status.success() {
            return Err(SimulationError::CliCommand(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let transaction_xdr = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if transaction_xdr.is_empty() {
            return Err(SimulationError::CliCommand(
                "command returned empty transaction XDR".into(),
            ));
        }
        Ok(transaction_xdr)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub instructions: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub resource_fee: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationEvidence {
    pub scenario: String,
    pub network: String,
    pub latest_ledger: Option<u64>,
    pub target: String,
    pub return_value_xdr: Option<String>,
    pub authorization_xdr: Vec<String>,
    pub resources: ResourceUsage,
    pub diagnostic_failure: Option<String>,
    pub success: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceThresholds {
    pub maximum_instruction_increase_bps: Option<u64>,
    pub maximum_read_byte_increase_bps: Option<u64>,
    pub maximum_write_byte_increase_bps: Option<u64>,
    pub maximum_resource_fee_increase_bps: Option<u64>,
}

pub fn compare_authorization(current: &[String], candidate: &[String]) -> Vec<Finding> {
    if current == candidate {
        return Vec::new();
    }
    vec![Finding::new(
        "AUTH001",
        Severity::Warning,
        "Runtime authorization changed",
        "The normalized authorization entries differ between current and candidate simulations.",
    )]
}

fn exceeds(current: Option<u64>, candidate: Option<u64>, bps: Option<u64>) -> bool {
    match (current, candidate, bps) {
        (Some(old), Some(new), Some(limit)) if old > 0 => {
            u128::from(new) * 10_000 > u128::from(old) * u128::from(10_000 + limit)
        }
        _ => false,
    }
}

pub fn compare_resources(
    current: &ResourceUsage,
    candidate: &ResourceUsage,
    limits: &ResourceThresholds,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (changed, label) in [
        (
            exceeds(
                current.instructions,
                candidate.instructions,
                limits.maximum_instruction_increase_bps,
            ),
            "instructions",
        ),
        (
            exceeds(
                current.read_bytes,
                candidate.read_bytes,
                limits.maximum_read_byte_increase_bps,
            ),
            "read bytes",
        ),
        (
            exceeds(
                current.write_bytes,
                candidate.write_bytes,
                limits.maximum_write_byte_increase_bps,
            ),
            "write bytes",
        ),
        (
            exceeds(
                current.resource_fee,
                candidate.resource_fee,
                limits.maximum_resource_fee_increase_bps,
            ),
            "resource fee",
        ),
    ] {
        if changed {
            findings.push(Finding::new(
                "RESOURCE001",
                Severity::Warning,
                "Resource threshold exceeded",
                format!("Candidate {label} exceed the configured increase threshold."),
            ));
        }
    }
    findings
}

pub async fn stellar_cli_version() -> Result<String, SimulationError> {
    let output = Command::new("stellar")
        .arg("version")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| SimulationError::Cli(e.to_string()))?;
    if !output.status.success() {
        return Err(SimulationError::Cli(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let version = text.split_whitespace().nth(1).unwrap_or_default();
    if !version.starts_with("28.") {
        return Err(SimulationError::CliVersion(version.into()));
    }
    Ok(text)
}

pub struct RpcClient {
    endpoint: Url,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(endpoint: &str, request_timeout: Duration) -> Result<Self, SimulationError> {
        let endpoint = Url::parse(endpoint).map_err(|e| SimulationError::Url(e.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(SimulationError::Url(
                "only http and https are supported".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| SimulationError::Rpc(e.to_string()))?;
        Ok(Self { endpoint, client })
    }

    pub fn sanitized_endpoint(&self) -> String {
        let mut url = self.endpoint.clone();
        let _ = url.set_username("");
        let _ = url.set_password(None);
        url.set_query(None);
        url.to_string()
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, SimulationError> {
        let body = json!({"jsonrpc":"2.0","id":"upgraderail","method":method,"params":params});
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SimulationError::Timeout
                } else {
                    SimulationError::Rpc(e.to_string())
                }
            })?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|e| SimulationError::Malformed(e.to_string()))?;
        if !status.is_success() {
            return Err(SimulationError::Rpc(format!("HTTP {status}")));
        }
        if let Some(error) = value.get("error") {
            return Err(SimulationError::JsonRpc(error.to_string()));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| SimulationError::Malformed("missing result".into()))
    }

    pub async fn get_health(&self) -> Result<Value, SimulationError> {
        self.call("getHealth", json!({})).await
    }
    pub async fn simulate_transaction(
        &self,
        transaction_xdr: &str,
        auth_mode: &str,
    ) -> Result<Value, SimulationError> {
        if !matches!(auth_mode, "enforce" | "record" | "record_allow_nonroot") {
            return Err(SimulationError::Rpc("invalid authorization mode".into()));
        }
        self.call(
            "simulateTransaction",
            json!({"transaction": transaction_xdr, "authMode": auth_mode}),
        )
        .await
    }
}

pub async fn run_with_timeout<F, T>(duration: Duration, future: F) -> Result<T, SimulationError>
where
    F: std::future::Future<Output = Result<T, SimulationError>>,
{
    timeout(duration, future)
        .await
        .map_err(|_| SimulationError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_difference_is_visible() {
        assert_eq!(
            compare_authorization(&["a".into()], &["b".into()])[0].code,
            "AUTH001"
        );
    }
    #[test]
    fn integer_resource_thresholds_are_enforced() {
        let old = ResourceUsage {
            instructions: Some(100),
            ..Default::default()
        };
        let new = ResourceUsage {
            instructions: Some(111),
            ..Default::default()
        };
        let limits = ResourceThresholds {
            maximum_instruction_increase_bps: Some(1000),
            ..Default::default()
        };
        assert_eq!(compare_resources(&old, &new, &limits).len(), 1);
    }
    #[test]
    fn rpc_secrets_are_removed() {
        let client = RpcClient::new(
            "https://user:pass@example.test/rpc?token=secret",
            Duration::from_secs(1),
        )
        .unwrap();
        let output = client.sanitized_endpoint();
        assert!(!output.contains("pass") && !output.contains("secret"));
    }

    fn invocation() -> ContractInvocation {
        ContractInvocation {
            contract_id: "CANDIDATE".into(),
            source_account: "GSOURCE".into(),
            rpc_url: "https://rpc.test".into(),
            network_passphrase: "network".into(),
            function: "set_value".into(),
            args: BTreeMap::from([("value".into(), "7".into())]),
            authorization_mode: AuthorizationMode::Record,
        }
    }

    #[test]
    fn transaction_builder_uses_individual_supported_cli_arguments() {
        assert_eq!(
            StellarCli::build_args(&invocation()),
            vec![
                "contract",
                "invoke",
                "--build-only",
                "--send",
                "no",
                "--contract-id",
                "CANDIDATE",
                "--source-account",
                "GSOURCE",
                "--rpc-url",
                "https://rpc.test",
                "--network-passphrase",
                "network",
                "--auth-mode",
                "root",
                "--",
                "set_value",
                "--value",
                "7",
            ]
        );
    }

    #[tokio::test]
    async fn transaction_builder_surfaces_failed_command_stderr() {
        let cli = StellarCli::with_program("/bin/false");
        assert!(matches!(
            cli.build_transaction(&invocation()).await,
            Err(SimulationError::CliCommand(_))
        ));
    }
}

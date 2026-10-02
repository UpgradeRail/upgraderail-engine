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

fn parse_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
}

pub fn decode_simulation_evidence(
    scenario: &str,
    network: &str,
    target: &str,
    response: &Value,
) -> Result<SimulationEvidence, SimulationError> {
    let result = response
        .get("results")
        .and_then(Value::as_array)
        .and_then(|results| results.first())
        .ok_or_else(|| {
            SimulationError::Malformed("simulateTransaction response has no results".into())
        })?;
    let authorization_xdr = result
        .get("auth")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let diagnostic_failure = result.get("error").map(Value::to_string);
    let cost = response.get("cost");
    Ok(SimulationEvidence {
        scenario: scenario.into(),
        network: network.into(),
        target: target.into(),
        latest_ledger: parse_u64(response.get("latestLedger")),
        return_value_xdr: result.get("xdr").and_then(Value::as_str).map(str::to_owned),
        authorization_xdr,
        resources: ResourceUsage {
            instructions: parse_u64(cost.and_then(|cost| cost.get("cpuInsns"))),
            read_bytes: parse_u64(cost.and_then(|cost| cost.get("readBytes"))),
            write_bytes: parse_u64(cost.and_then(|cost| cost.get("writeBytes"))),
            resource_fee: parse_u64(response.get("minResourceFee")),
        },
        success: diagnostic_failure.is_none(),
        diagnostic_failure,
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceThresholds {
    pub maximum_instruction_increase_bps: Option<u64>,
    pub maximum_read_byte_increase_bps: Option<u64>,
    pub maximum_write_byte_increase_bps: Option<u64>,
    pub maximum_resource_fee_increase_bps: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioComparison {
    pub current: SimulationEvidence,
    pub candidate: SimulationEvidence,
    pub findings: Vec<Finding>,
}

pub async fn run_scenario(
    cli: &StellarCli,
    scenario: &SimulationScenario,
    thresholds: &ResourceThresholds,
) -> Result<ScenarioComparison, SimulationError> {
    let rpc = RpcClient::new(&scenario.network.rpc_url, Duration::from_secs(30))?;
    let build = |contract_id: &str| ContractInvocation {
        contract_id: contract_id.into(),
        source_account: scenario.source_account.clone(),
        rpc_url: scenario.network.rpc_url.clone(),
        network_passphrase: scenario.network.network_passphrase.clone(),
        function: scenario.function.clone(),
        args: scenario.args.clone(),
        authorization_mode: scenario.authorization_mode,
    };
    let current_transaction = cli
        .build_transaction(&build(&scenario.current_contract))
        .await?;
    let current_response = rpc
        .simulate_transaction(
            &current_transaction,
            scenario.authorization_mode.rpc_value(),
        )
        .await?;
    let current = decode_simulation_evidence(
        &scenario.name,
        &scenario.network.name,
        &scenario.current_contract,
        &current_response,
    )?;
    let candidate_transaction = cli
        .build_transaction(&build(&scenario.candidate_contract))
        .await?;
    let candidate_response = rpc
        .simulate_transaction(
            &candidate_transaction,
            scenario.authorization_mode.rpc_value(),
        )
        .await?;
    let candidate = decode_simulation_evidence(
        &scenario.name,
        &scenario.network.name,
        &scenario.candidate_contract,
        &candidate_response,
    )?;
    let findings = compare_scenario_evidence(scenario, &current, &candidate, thresholds);
    Ok(ScenarioComparison {
        current,
        candidate,
        findings,
    })
}

pub fn compare_scenario_evidence(
    scenario: &SimulationScenario,
    current: &SimulationEvidence,
    candidate: &SimulationEvidence,
    thresholds: &ResourceThresholds,
) -> Vec<Finding> {
    let mut findings =
        compare_authorization(&current.authorization_xdr, &candidate.authorization_xdr);
    findings.extend(compare_resources(
        &current.resources,
        &candidate.resources,
        thresholds,
    ));
    if scenario.expectations.return_match && current.return_value_xdr != candidate.return_value_xdr
    {
        findings.push(Finding::new(
            "SIM002",
            Severity::Warning,
            "Runtime return value changed",
            "Current and candidate scenarios returned different XDR values.",
        ));
    }
    if !current.success || !candidate.success {
        findings.push(Finding::new(
            "SIM003",
            Severity::Warning,
            "Simulation failed",
            "At least one current or candidate simulation returned a diagnostic failure.",
        ));
    }
    findings.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    findings
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
    fn resource_thresholds_handle_boundaries_and_absent_values() {
        let limits = ResourceThresholds {
            maximum_instruction_increase_bps: Some(1_000),
            ..Default::default()
        };
        let current = ResourceUsage {
            instructions: Some(100),
            ..Default::default()
        };
        assert!(compare_resources(
            &current,
            &ResourceUsage {
                instructions: Some(110),
                ..Default::default()
            },
            &limits
        )
        .is_empty());
        assert_eq!(
            compare_resources(
                &current,
                &ResourceUsage {
                    instructions: Some(111),
                    ..Default::default()
                },
                &limits
            )
            .len(),
            1
        );
        assert!(compare_resources(
            &ResourceUsage {
                instructions: Some(0),
                ..Default::default()
            },
            &ResourceUsage {
                instructions: Some(u64::MAX),
                ..Default::default()
            },
            &limits
        )
        .is_empty());
        assert!(compare_resources(&current, &ResourceUsage::default(), &limits).is_empty());
        assert!(
            compare_resources(
                &current,
                &ResourceUsage {
                    instructions: Some(u64::MAX),
                    ..Default::default()
                },
                &limits
            )
            .len()
                == 1
        );
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

    #[test]
    fn rpc_simulation_evidence_decodes_supported_fields() {
        let response = json!({
            "latestLedger": 42,
            "minResourceFee": "17",
            "cost": { "cpuInsns": "100", "readBytes": "3", "writeBytes": "4" },
            "results": [{ "xdr": "AAAA", "auth": ["AUTH"] }]
        });
        let evidence =
            decode_simulation_evidence("scenario", "testnet", "C123", &response).unwrap();
        assert_eq!(evidence.latest_ledger, Some(42));
        assert_eq!(evidence.return_value_xdr.as_deref(), Some("AAAA"));
        assert_eq!(evidence.authorization_xdr, ["AUTH"]);
        assert_eq!(evidence.resources.resource_fee, Some(17));
        assert!(evidence.success);
    }

    #[test]
    fn rpc_simulation_evidence_rejects_missing_results() {
        assert!(matches!(
            decode_simulation_evidence("scenario", "testnet", "C123", &json!({})),
            Err(SimulationError::Malformed(_))
        ));
    }

    #[test]
    fn scenario_evidence_compares_return_values_and_failures() {
        let scenario = SimulationScenario {
            name: "test".into(),
            network: ScenarioNetwork {
                name: "testnet".into(),
                rpc_url: "https://rpc.test".into(),
                network_passphrase: "test".into(),
            },
            source_account: "G".into(),
            current_contract: "C1".into(),
            candidate_contract: "C2".into(),
            function: "get".into(),
            args: BTreeMap::new(),
            authorization_mode: AuthorizationMode::Record,
            expectations: ScenarioExpectations {
                return_match: true,
                authorization_match: true,
            },
        };
        let current = SimulationEvidence {
            scenario: "test".into(),
            network: "testnet".into(),
            target: "C1".into(),
            latest_ledger: None,
            return_value_xdr: Some("A".into()),
            authorization_xdr: vec![],
            resources: ResourceUsage::default(),
            diagnostic_failure: None,
            success: true,
        };
        let candidate = SimulationEvidence {
            target: "C2".into(),
            return_value_xdr: Some("B".into()),
            diagnostic_failure: Some("failure".into()),
            success: false,
            ..current.clone()
        };
        let findings = compare_scenario_evidence(
            &scenario,
            &current,
            &candidate,
            &ResourceThresholds::default(),
        );
        assert!(findings.iter().any(|finding| finding.code == "SIM002"));
        assert!(findings.iter().any(|finding| finding.code == "SIM003"));
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

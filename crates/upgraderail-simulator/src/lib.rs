use serde::{Deserialize, Serialize};
use upgraderail_core::{Finding, Severity};

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("Stellar CLI is unavailable: {0}")]
    Cli(String),
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

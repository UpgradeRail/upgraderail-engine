use serde::{Deserialize, Serialize};

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

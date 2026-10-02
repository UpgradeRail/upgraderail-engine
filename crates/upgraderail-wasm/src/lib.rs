use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
};
use upgraderail_core::ProtocolProfile;

pub const MAX_WASM_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("cannot read WASM {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("WASM exceeds the {MAX_WASM_BYTES}-byte input limit: {0} bytes")]
    TooLarge(u64),
    #[error("invalid WASM: {0}")]
    Invalid(String),
    #[error("Soroban contract specification is missing")]
    SpecMissing,
    #[error("invalid Soroban contract specification: {0}")]
    Spec(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub name: String,
    pub inputs: Vec<serde_json::Value>,
    pub outputs: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedSpec {
    pub name: String,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactInspection {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub valid_wasm: bool,
    pub soroban_spec_present: bool,
    pub soroban_metadata_present: bool,
    pub functions: Vec<FunctionSpec>,
    pub types: Vec<NamedSpec>,
    pub errors: Vec<NamedSpec>,
    pub events: Vec<NamedSpec>,
    pub custom_sections: Vec<String>,
    pub protocol_profile: ProtocolProfile,
    pub tool_version: String,
}

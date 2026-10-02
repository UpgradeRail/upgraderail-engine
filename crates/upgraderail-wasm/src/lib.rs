use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soroban_spec::read;
use std::{
    fs,
    path::{Path, PathBuf},
};
use stellar_xdr::ScSpecEntry;
use upgraderail_core::ProtocolProfile;
use wasmparser::{Parser, Payload, Validator};

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

type NormalizedSpec = (
    Vec<FunctionSpec>,
    Vec<NamedSpec>,
    Vec<NamedSpec>,
    Vec<NamedSpec>,
);

fn xdr_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.get("name").cloned())
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unnamed>".into())
}

fn normalize(entries: Vec<ScSpecEntry>) -> Result<NormalizedSpec, InspectError> {
    let mut functions = Vec::new();
    let mut types = Vec::new();
    let mut errors = Vec::new();
    let mut events = Vec::new();
    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(v) => {
                let value =
                    serde_json::to_value(&v).map_err(|e| InspectError::Spec(e.to_string()))?;
                functions.push(FunctionSpec {
                    name: xdr_name(&v),
                    inputs: value
                        .get("inputs")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default(),
                    outputs: value
                        .get("outputs")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            ScSpecEntry::UdtErrorEnumV0(v) => errors.push(NamedSpec {
                name: xdr_name(&v),
                value: serde_json::to_value(v).map_err(|e| InspectError::Spec(e.to_string()))?,
            }),
            ScSpecEntry::EventV0(v) => events.push(NamedSpec {
                name: xdr_name(&v),
                value: serde_json::to_value(v).map_err(|e| InspectError::Spec(e.to_string()))?,
            }),
            ScSpecEntry::UdtStructV0(v) => types.push(NamedSpec {
                name: xdr_name(&v),
                value: serde_json::to_value(v).map_err(|e| InspectError::Spec(e.to_string()))?,
            }),
            ScSpecEntry::UdtUnionV0(v) => types.push(NamedSpec {
                name: xdr_name(&v),
                value: serde_json::to_value(v).map_err(|e| InspectError::Spec(e.to_string()))?,
            }),
            ScSpecEntry::UdtEnumV0(v) => types.push(NamedSpec {
                name: xdr_name(&v),
                value: serde_json::to_value(v).map_err(|e| InspectError::Spec(e.to_string()))?,
            }),
        }
    }
    functions.sort_by(|a, b| a.name.cmp(&b.name));
    types.sort_by(|a, b| a.name.cmp(&b.name));
    errors.sort_by(|a, b| a.name.cmp(&b.name));
    events.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((functions, types, errors, events))
}

pub fn inspect(
    path: impl AsRef<Path>,
    profile: ProtocolProfile,
) -> Result<ArtifactInspection, InspectError> {
    let path = path.as_ref();
    let metadata = fs::metadata(path).map_err(|source| InspectError::Read {
        path: path.into(),
        source,
    })?;
    if metadata.len() > MAX_WASM_BYTES {
        return Err(InspectError::TooLarge(metadata.len()));
    }
    let bytes = fs::read(path).map_err(|source| InspectError::Read {
        path: path.into(),
        source,
    })?;
    Validator::new()
        .validate_all(&bytes)
        .map_err(|e| InspectError::Invalid(e.to_string()))?;
    let mut custom_sections = Vec::new();
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Payload::CustomSection(s) =
            payload.map_err(|e| InspectError::Invalid(e.to_string()))?
        {
            custom_sections.push(s.name().to_owned());
        }
    }
    custom_sections.sort();
    custom_sections.dedup();
    let entries = read::from_wasm(&bytes).map_err(|e| match e {
        read::FromWasmError::NotFound => InspectError::SpecMissing,
        other => InspectError::Spec(other.to_string()),
    })?;
    let (functions, types, errors, events) = normalize(entries)?;
    Ok(ArtifactInspection {
        path: path.into(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        size_bytes: metadata.len(),
        valid_wasm: true,
        soroban_spec_present: true,
        soroban_metadata_present: custom_sections.iter().any(|s| s == "contractmetav0"),
        functions,
        types,
        errors,
        events,
        custom_sections,
        protocol_profile: profile,
        tool_version: env!("CARGO_PKG_VERSION").into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_wasm_is_a_clean_error() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not wasm").unwrap();
        assert!(matches!(
            inspect(file.path(), ProtocolProfile::Protocol28),
            Err(InspectError::Invalid(_))
        ));
    }
}

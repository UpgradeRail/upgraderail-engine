use crate::{FunctionSpec, InspectError, NamedSpec};
use serde::Serialize;
use soroban_spec::read;
use stellar_xdr::ScSpecEntry;

pub type NormalizedSpec = (
    Vec<FunctionSpec>,
    Vec<NamedSpec>,
    Vec<NamedSpec>,
    Vec<NamedSpec>,
);

pub fn extract(bytes: &[u8]) -> Result<NormalizedSpec, InspectError> {
    let entries = read::from_wasm(bytes).map_err(|error| match error {
        read::FromWasmError::NotFound => InspectError::SpecMissing,
        other => InspectError::Spec(other.to_string()),
    })?;
    normalize(entries)
}

fn xdr_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.get("name").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<unnamed>".into())
}
fn named<T: Serialize>(value: T) -> Result<NamedSpec, InspectError> {
    Ok(NamedSpec {
        name: xdr_name(&value),
        value: serde_json::to_value(value)
            .map_err(|error| InspectError::Spec(error.to_string()))?,
    })
}
fn normalize(entries: Vec<ScSpecEntry>) -> Result<NormalizedSpec, InspectError> {
    let mut functions = Vec::new();
    let mut types = Vec::new();
    let mut errors = Vec::new();
    let mut events = Vec::new();
    for entry in entries {
        match entry {
            ScSpecEntry::FunctionV0(value) => {
                let json = serde_json::to_value(&value)
                    .map_err(|error| InspectError::Spec(error.to_string()))?;
                functions.push(FunctionSpec {
                    name: xdr_name(&value),
                    inputs: json
                        .get("inputs")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default(),
                    outputs: json
                        .get("outputs")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default(),
                });
            }
            ScSpecEntry::UdtErrorEnumV0(value) => errors.push(named(value)?),
            ScSpecEntry::EventV0(value) => events.push(named(value)?),
            ScSpecEntry::UdtStructV0(value) => types.push(named(value)?),
            ScSpecEntry::UdtUnionV0(value) => types.push(named(value)?),
            ScSpecEntry::UdtEnumV0(value) => types.push(named(value)?),
        }
    }
    functions.sort_by(|left, right| left.name.cmp(&right.name));
    types.sort_by(|left, right| left.name.cmp(&right.name));
    errors.sort_by(|left, right| left.name.cmp(&right.name));
    events.sort_by(|left, right| left.name.cmp(&right.name));
    Ok((functions, types, errors, events))
}

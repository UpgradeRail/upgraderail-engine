use crate::{InspectError, MAX_WASM_BYTES};
use std::{fs, path::Path};
use wasmparser::Validator;

pub fn read_valid_wasm(path: &Path) -> Result<Vec<u8>, InspectError> {
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
        .map_err(|error| InspectError::Invalid(error.to_string()))?;
    Ok(bytes)
}

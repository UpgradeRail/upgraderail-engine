use crate::{hash, metadata, spec, validation, ArtifactInspection, InspectError};
use std::path::Path;
use upgraderail_core::ProtocolProfile;

pub fn inspect(
    path: impl AsRef<Path>,
    profile: ProtocolProfile,
) -> Result<ArtifactInspection, InspectError> {
    let path = path.as_ref();
    let bytes = validation::read_valid_wasm(path)?;
    let custom_sections = metadata::custom_sections(&bytes)?;
    let (functions, types, errors, events) = spec::extract(&bytes)?;
    Ok(ArtifactInspection {
        path: path.into(),
        sha256: hash::sha256(&bytes),
        size_bytes: bytes.len() as u64,
        valid_wasm: true,
        soroban_spec_present: true,
        soroban_metadata_present: custom_sections
            .iter()
            .any(|section| section == "contractmetav0"),
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
    use crate::MAX_WASM_BYTES;
    use tempfile::NamedTempFile;
    #[test]
    fn malformed_and_truncated_wasm_are_clean_errors() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"\0asm").unwrap();
        assert!(matches!(
            inspect(file.path(), ProtocolProfile::Protocol28),
            Err(InspectError::Invalid(_))
        ));
    }
    #[test]
    fn oversized_wasm_is_rejected_before_parsing() {
        let file = NamedTempFile::new().unwrap();
        file.as_file().set_len(MAX_WASM_BYTES + 1).unwrap();
        assert!(matches!(
            inspect(file.path(), ProtocolProfile::Protocol28),
            Err(InspectError::TooLarge(_))
        ));
    }
    #[test]
    fn valid_wasm_without_soroban_spec_is_reported() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"\0asm\x01\0\0\0").unwrap();
        assert!(matches!(
            inspect(file.path(), ProtocolProfile::Protocol28),
            Err(InspectError::SpecMissing)
        ));
    }
}

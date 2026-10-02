use crate::InspectError;
use wasmparser::{Parser, Payload};

pub fn custom_sections(bytes: &[u8]) -> Result<Vec<String>, InspectError> {
    let mut sections = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CustomSection(section) =
            payload.map_err(|error| InspectError::Invalid(error.to_string()))?
        {
            sections.push(section.name().to_owned());
        }
    }
    sections.sort();
    sections.dedup();
    Ok(sections)
}

use upgraderail_analyzer::AnalysisResult;
use upgraderail_core::Severity;
use upgraderail_manifest::ReleaseManifest;
use upgraderail_wasm::ArtifactInspection;

pub fn inspection_text(value: &ArtifactInspection) -> String {
    format!(
        "UpgradeRail Artifact Inspection\n\nPath: {}\nSHA-256: {}\nSize: {} bytes\nValid WASM: YES\nSoroban specification: PRESENT\nSoroban metadata: {}\nFunctions: {}\nTypes: {}\nErrors: {}\nEvents: {}\nProtocol profile: {}\n",
        value.path.display(), value.sha256, value.size_bytes,
        if value.soroban_metadata_present { "PRESENT" } else { "NOT AVAILABLE" },
        value.functions.len(), value.types.len(), value.errors.len(), value.events.len(), value.protocol_profile,
    )
}

pub fn analysis_text(
    current: &ArtifactInspection,
    candidate: &ArtifactInspection,
    result: &AnalysisResult,
) -> String {
    let mut text = format!("UpgradeRail Preflight\n\nCurrent\n  WASM  {}\n  Size  {} bytes\n\nCandidate\n  WASM  {}\n  Size  {} bytes\n\nStatic analysis\n", current.sha256, current.size_bytes, candidate.sha256, candidate.size_bytes);
    for finding in &result.findings {
        let label = match finding.severity {
            Severity::Blocking => "BLOCK",
            Severity::Warning => "WARN ",
            Severity::Info => "INFO ",
        };
        text.push_str(&format!(
            "  {label}  {}: {}\n",
            finding.code, finding.message
        ));
    }
    text.push_str(&format!(
        "\nStorage compatibility: {}\nAuthorization behavior: {}\n\nResult\n  {}\n",
        result.storage_compatibility, result.authorization_behavior, result.status
    ));
    text
}

pub fn analysis_markdown(result: &AnalysisResult) -> String {
    let mut text = format!("# UpgradeRail Preflight\n\n**Result: {}**\n\n| Severity | Code | Finding |\n|---|---|---|\n", result.status);
    for finding in &result.findings {
        text.push_str(&format!(
            "| {:?} | `{}` | {} |\n",
            finding.severity,
            finding.code,
            finding.message.replace('|', "\\|")
        ));
    }
    text.push_str(&format!(
        "\n- Storage compatibility: {}\n- Authorization behavior: {}\n",
        result.storage_compatibility, result.authorization_behavior
    ));
    text
}

pub fn manifest_markdown(manifest: &ReleaseManifest) -> String {
    analysis_markdown(&manifest.analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use upgraderail_analyzer::AnalysisResult;
    use upgraderail_core::UpgradeStatus;
    #[test]
    fn absent_runtime_checks_are_not_rendered_as_pass() {
        let result = AnalysisResult {
            status: UpgradeStatus::Ready,
            findings: vec![],
            storage_compatibility: "NOT PROVEN BY STATIC ANALYSIS".into(),
            authorization_behavior: "NOT TESTED".into(),
        };
        let output = analysis_markdown(&result);
        assert!(output.contains("NOT TESTED") && !output.contains("Authorization behavior: PASS"));
    }
}

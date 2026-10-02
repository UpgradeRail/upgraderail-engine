use crate::{rules, AnalysisResult};
use upgraderail_core::{Finding, Severity, UpgradeStatus};
use upgraderail_wasm::ArtifactInspection;

pub fn analyze(current: &ArtifactInspection, candidate: &ArtifactInspection) -> AnalysisResult {
    let mut findings = Vec::new();
    rules::functions::compare(&current.functions, &candidate.functions, &mut findings);
    rules::named::compare(
        &current.types,
        &candidate.types,
        "TYPE001",
        "TYPE002",
        "TYPE003",
        "type",
        &mut findings,
    );
    rules::named::compare(
        &current.errors,
        &candidate.errors,
        "ERROR001",
        "ERROR002",
        "ERROR003",
        "error definition",
        &mut findings,
    );
    rules::named::compare(
        &current.events,
        &candidate.events,
        "EVENT001",
        "EVENT002",
        "EVENT003",
        "event",
        &mut findings,
    );
    if current.soroban_metadata_present != candidate.soroban_metadata_present {
        findings.push(Finding::new(
            "META001",
            Severity::Warning,
            "Soroban metadata presence changed",
            "The current and candidate artifacts do not have the same metadata-section presence.",
        ));
    }
    findings.push(Finding::new("SPEC010", Severity::Info, "Storage compatibility is not statically proven", "Soroban contract specifications do not expose all private storage keys or state invariants. Run an explicit migration scenario."));
    findings.sort_by(|left, right| {
        (&left.code, &left.title, &left.message).cmp(&(&right.code, &right.title, &right.message))
    });
    AnalysisResult {
        status: UpgradeStatus::from_findings(&findings),
        findings,
        storage_compatibility: "NOT PROVEN BY STATIC ANALYSIS".into(),
        authorization_behavior: "NOT TESTED".into(),
    }
}

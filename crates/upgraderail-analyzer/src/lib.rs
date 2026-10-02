use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use upgraderail_core::{Evidence, Finding, Severity, UpgradeStatus};
use upgraderail_wasm::{ArtifactInspection, FunctionSpec, NamedSpec};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub status: UpgradeStatus,
    pub findings: Vec<Finding>,
    pub storage_compatibility: String,
    pub authorization_behavior: String,
}

fn evidence(kind: &str, reference: &str) -> Vec<Evidence> {
    vec![Evidence {
        kind: kind.into(),
        reference: reference.into(),
    }]
}

fn compare_functions(current: &[FunctionSpec], candidate: &[FunctionSpec], out: &mut Vec<Finding>) {
    let old: BTreeMap<_, _> = current.iter().map(|f| (&f.name, f)).collect();
    let new: BTreeMap<_, _> = candidate.iter().map(|f| (&f.name, f)).collect();
    for (name, function) in &old {
        match new.get(name) {
            None => {
                let mut finding = Finding::new(
                    "FUNC001",
                    Severity::Blocking,
                    "Public function removed",
                    format!("Function `{name}` is absent from the candidate contract."),
                );
                finding.evidence = evidence("current_function", name);
                out.push(finding);
            }
            Some(candidate_function) => {
                if function.inputs != candidate_function.inputs {
                    let mut finding = Finding::new(
                        "FUNC002",
                        Severity::Blocking,
                        "Function inputs changed",
                        format!("Function `{name}` has incompatible input definitions."),
                    );
                    finding.evidence = evidence("function", name);
                    out.push(finding);
                }
                if function.outputs != candidate_function.outputs {
                    let mut finding = Finding::new(
                        "FUNC003",
                        Severity::Blocking,
                        "Function return changed",
                        format!("Function `{name}` has an incompatible return definition."),
                    );
                    finding.evidence = evidence("function", name);
                    out.push(finding);
                }
            }
        }
    }
    for name in new.keys().filter(|name| !old.contains_key(*name)) {
        let mut finding = Finding::new(
            "FUNC004",
            Severity::Info,
            "Public function added",
            format!("Function `{name}` was added by the candidate contract."),
        );
        finding.evidence = evidence("candidate_function", name);
        out.push(finding);
    }
}

fn compare_named(
    current: &[NamedSpec],
    candidate: &[NamedSpec],
    removed_code: &str,
    changed_code: &str,
    added_code: &str,
    noun: &str,
    out: &mut Vec<Finding>,
) {
    let old: BTreeMap<_, _> = current.iter().map(|v| (&v.name, v)).collect();
    let new: BTreeMap<_, _> = candidate.iter().map(|v| (&v.name, v)).collect();
    for (name, value) in &old {
        match new.get(name) {
            None => out.push(Finding::new(
                removed_code,
                Severity::Blocking,
                format!("Public {noun} removed").as_str(),
                format!("{noun} `{name}` is absent from the candidate contract."),
            )),
            Some(other) if value.value != other.value => out.push(Finding::new(
                changed_code,
                Severity::Blocking,
                format!("Public {noun} changed").as_str(),
                format!("{noun} `{name}` changed incompatibly."),
            )),
            _ => {}
        }
    }
    for name in new.keys().filter(|name| !old.contains_key(*name)) {
        out.push(Finding::new(
            added_code,
            Severity::Info,
            format!("Public {noun} added").as_str(),
            format!("{noun} `{name}` was added."),
        ));
    }
}

pub fn analyze(current: &ArtifactInspection, candidate: &ArtifactInspection) -> AnalysisResult {
    let mut findings = Vec::new();
    compare_functions(&current.functions, &candidate.functions, &mut findings);
    compare_named(
        &current.types,
        &candidate.types,
        "TYPE001",
        "TYPE002",
        "TYPE003",
        "type",
        &mut findings,
    );
    compare_named(
        &current.errors,
        &candidate.errors,
        "ERROR001",
        "ERROR002",
        "ERROR003",
        "error definition",
        &mut findings,
    );
    compare_named(
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
    findings.sort_by(|a, b| (&a.code, &a.title, &a.message).cmp(&(&b.code, &b.title, &b.message)));
    AnalysisResult {
        status: UpgradeStatus::from_findings(&findings),
        findings,
        storage_compatibility: "NOT PROVEN BY STATIC ANALYSIS".into(),
        authorization_behavior: "NOT TESTED".into(),
    }
}

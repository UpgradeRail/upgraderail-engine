use std::collections::BTreeMap;
use upgraderail_core::{Evidence, Finding, Severity};
use upgraderail_wasm::FunctionSpec;

pub fn compare(current: &[FunctionSpec], candidate: &[FunctionSpec], out: &mut Vec<Finding>) {
    let old: BTreeMap<_, _> = current
        .iter()
        .map(|function| (&function.name, function))
        .collect();
    let new: BTreeMap<_, _> = candidate
        .iter()
        .map(|function| (&function.name, function))
        .collect();
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
fn evidence(kind: &str, reference: &str) -> Vec<Evidence> {
    vec![Evidence {
        kind: kind.into(),
        reference: reference.into(),
    }]
}

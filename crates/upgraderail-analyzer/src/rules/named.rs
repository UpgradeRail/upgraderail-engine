use std::collections::BTreeMap;
use upgraderail_core::{Finding, Severity};
use upgraderail_wasm::NamedSpec;

pub fn compare(
    current: &[NamedSpec],
    candidate: &[NamedSpec],
    removed_code: &str,
    changed_code: &str,
    added_code: &str,
    noun: &str,
    out: &mut Vec<Finding>,
) {
    let old: BTreeMap<_, _> = current.iter().map(|value| (&value.name, value)).collect();
    let new: BTreeMap<_, _> = candidate.iter().map(|value| (&value.name, value)).collect();
    for (name, value) in &old {
        match new.get(name) {
            None => out.push(Finding::new(
                removed_code,
                Severity::Blocking,
                &format!("Public {noun} removed"),
                format!("{noun} `{name}` is absent from the candidate contract."),
            )),
            Some(other) if value.value != other.value => out.push(Finding::new(
                changed_code,
                Severity::Blocking,
                &format!("Public {noun} changed"),
                format!("{noun} `{name}` changed incompatibly."),
            )),
            _ => {}
        }
    }
    for name in new.keys().filter(|name| !old.contains_key(*name)) {
        out.push(Finding::new(
            added_code,
            Severity::Info,
            &format!("Public {noun} added"),
            format!("{noun} `{name}` was added."),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_removed_changed_and_added_named_definitions() {
        let current = vec![
            NamedSpec {
                name: "old".into(),
                value: serde_json::json!(1),
            },
            NamedSpec {
                name: "changed".into(),
                value: serde_json::json!(1),
            },
        ];
        let candidate = vec![
            NamedSpec {
                name: "changed".into(),
                value: serde_json::json!(2),
            },
            NamedSpec {
                name: "added".into(),
                value: serde_json::json!(3),
            },
        ];
        let mut findings = Vec::new();
        compare(
            &current,
            &candidate,
            "TYPE001",
            "TYPE002",
            "TYPE003",
            "type",
            &mut findings,
        );
        let codes = findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>();
        assert!(
            codes.contains(&"TYPE001") && codes.contains(&"TYPE002") && codes.contains(&"TYPE003")
        );
    }
}

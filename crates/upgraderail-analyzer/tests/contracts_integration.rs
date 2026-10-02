use std::path::{Path, PathBuf};
use upgraderail_analyzer::analyze;
use upgraderail_core::{ProtocolProfile, Severity};
use upgraderail_wasm::{inspect, ArtifactInspection};

fn contracts_repo() -> PathBuf {
    std::env::var_os("UPGRADERAIL_CONTRACTS_DIR")
        .map(Into::into)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../upgraderail-contracts")
        })
}

fn fixture(name: &str) -> ArtifactInspection {
    inspect(
        contracts_repo().join("fixtures/wasm").join(name),
        ProtocolProfile::Protocol28,
    )
    .unwrap()
}

#[test]
fn fleet_v1_to_compatible_has_no_false_interface_blocker() {
    let result = analyze(
        &fixture("fleet_v1.wasm"),
        &fixture("fleet_v2_compatible.wasm"),
    );
    assert!(!result
        .findings
        .iter()
        .any(|f| f.severity == Severity::Blocking));
    assert!(result.findings.iter().any(|f| f.code == "FUNC004"));
}

#[test]
fn fleet_v1_to_breaking_has_genuine_interface_blockers() {
    let result = analyze(
        &fixture("fleet_v1.wasm"),
        &fixture("fleet_v2_breaking.wasm"),
    );
    assert!(result
        .findings
        .iter()
        .any(|f| { f.severity == Severity::Blocking && f.code.starts_with("FUNC") }));
}

#[test]
fn fleet_v1_to_migration_does_not_claim_static_storage_proof() {
    let result = analyze(
        &fixture("fleet_v1.wasm"),
        &fixture("fleet_v2_migration.wasm"),
    );
    assert_eq!(
        result.storage_compatibility,
        "NOT PROVEN BY STATIC ANALYSIS"
    );
    assert!(result.findings.iter().any(|f| f.code == "SPEC010"));
}

#[test]
fn upgrade_controller_is_inspected_from_real_wasm() {
    let controller = fixture("upgrade_controller_v1.wasm");
    assert!(controller.valid_wasm);
    assert!(!controller.functions.is_empty());
}

#[test]
fn current_testnet_deployment_record_is_read_in_place() {
    let deployment =
        std::fs::read_to_string(contracts_repo().join("deployments/testnet.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&deployment).unwrap();
    assert_eq!(value["network"], "testnet");
    assert!(value["controller"]["contract_id"]
        .as_str()
        .is_some_and(|v| !v.is_empty()));
    assert!(value["controller"]["wasm_hash"]
        .as_str()
        .is_some_and(|v| v.len() == 64));
}

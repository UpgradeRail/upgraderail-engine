use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationMode {
    Enforce,
    #[default]
    Record,
    RecordAllowNonroot,
}

impl AuthorizationMode {
    #[must_use]
    pub const fn stellar_cli_value(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Record => "root",
            Self::RecordAllowNonroot => "non-root",
        }
    }

    #[must_use]
    pub const fn rpc_value(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Record => "record",
            Self::RecordAllowNonroot => "record_allow_nonroot",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioNetwork {
    pub name: String,
    pub rpc_url: String,
    pub network_passphrase: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScenarioExpectations {
    #[serde(default)]
    pub return_match: bool,
    #[serde(default)]
    pub authorization_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulationScenario {
    pub name: String,
    pub network: ScenarioNetwork,
    pub source_account: String,
    pub current_contract: String,
    pub candidate_contract: String,
    pub function: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    #[serde(default)]
    pub authorization_mode: AuthorizationMode,
    #[serde(default)]
    pub expectations: ScenarioExpectations,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_mode_maps_to_supported_cli_and_rpc_values() {
        assert_eq!(AuthorizationMode::Record.stellar_cli_value(), "root");
        assert_eq!(AuthorizationMode::Record.rpc_value(), "record");
    }

    #[test]
    fn scenario_arguments_are_deterministically_ordered() {
        let mut args: BTreeMap<String, String> = BTreeMap::new();
        args.insert("z".into(), "1".into());
        args.insert("a".into(), "2".into());
        assert_eq!(args.keys().cloned().collect::<Vec<_>>(), ["a", "z"]);
    }
}

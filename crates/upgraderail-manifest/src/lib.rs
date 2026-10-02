use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use upgraderail_analyzer::{analyze, AnalysisResult};
use upgraderail_core::{ProtocolProfile, UpgradeStatus};
use upgraderail_simulator::{ResourceThresholds, SimulationEvidence};
use upgraderail_wasm::{inspect, ArtifactInspection};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("cannot read `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("artifact inspection failed: {0}")]
    Inspect(String),
    #[error("manifest serialization failed: {0}")]
    Serialize(String),
    #[error("cannot write `{path}`: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub project: ProjectConfig,
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub resource_thresholds: ResourceThresholds,
    #[serde(default, rename = "simulation")]
    pub simulations: Vec<upgraderail_simulator::SimulationScenario>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub name: String,
    pub source_revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisConfig {
    pub protocol_profile: u32,
    pub current_wasm: PathBuf,
    pub candidate_wasm: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub require_simulation: bool,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ManifestError::Read {
            path: path.into(),
            source,
        })?;
        let mut config: Self =
            toml::from_str(&text).map_err(|e| ManifestError::Config(e.to_string()))?;
        if config.schema_version != 1 {
            return Err(ManifestError::Config(format!(
                "schema_version: unsupported value {}",
                config.schema_version
            )));
        }
        if config.analysis.protocol_profile != 28 {
            return Err(ManifestError::Config(
                "analysis.protocol_profile: only protocol 28 is supported".into(),
            ));
        }
        if config.project.name.trim().is_empty() {
            return Err(ManifestError::Config(
                "project.name: must not be empty".into(),
            ));
        }
        validate_scenarios(&config.simulations)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.analysis.current_wasm.is_relative() {
            config.analysis.current_wasm = base.join(&config.analysis.current_wasm);
        }
        if config.analysis.candidate_wasm.is_relative() {
            config.analysis.candidate_wasm = base.join(&config.analysis.candidate_wasm);
        }
        Ok(config)
    }
}

fn is_base32_strkey(value: &str, prefix: char) -> bool {
    value.len() == 56
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'2'..=b'7'))
}

fn validate_scenarios(
    scenarios: &[upgraderail_simulator::SimulationScenario],
) -> Result<(), ManifestError> {
    let mut names = std::collections::BTreeSet::new();
    for scenario in scenarios {
        if scenario.name.trim().is_empty() {
            return Err(ManifestError::Config(
                "simulation.name: must not be empty".into(),
            ));
        }
        if !names.insert(&scenario.name) {
            return Err(ManifestError::Config(format!(
                "simulation.name: duplicate scenario `{}`",
                scenario.name
            )));
        }
        if !is_base32_strkey(&scenario.source_account, 'G') {
            return Err(ManifestError::Config(format!(
                "simulation.{}.source_account: invalid Stellar account",
                scenario.name
            )));
        }
        for (field, value) in [
            ("current_contract", &scenario.current_contract),
            ("candidate_contract", &scenario.candidate_contract),
        ] {
            if !is_base32_strkey(value, 'C') {
                return Err(ManifestError::Config(format!(
                    "simulation.{}.{field}: invalid Stellar contract ID",
                    scenario.name
                )));
            }
        }
        if scenario.function.trim().is_empty() {
            return Err(ManifestError::Config(format!(
                "simulation.{}.function: must not be empty",
                scenario.name
            )));
        }
        let rpc_url = Url::parse(&scenario.network.rpc_url).map_err(|_| {
            ManifestError::Config(format!(
                "simulation.{}.network.rpc_url: invalid URL",
                scenario.name
            ))
        })?;
        if !matches!(rpc_url.scheme(), "http" | "https")
            || !rpc_url.username().is_empty()
            || rpc_url.password().is_some()
            || rpc_url.query().is_some()
        {
            return Err(ManifestError::Config(format!(
                "simulation.{}.network.rpc_url: use a credential-free http(s) endpoint",
                scenario.name
            )));
        }
        if scenario.network.name.trim().is_empty() || scenario.network.network_passphrase.is_empty()
        {
            return Err(ManifestError::Config(format!(
                "simulation.{}.network: name and network_passphrase are required",
                scenario.name
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub sha256: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

impl From<&ArtifactInspection> for ArtifactRecord {
    fn from(value: &ArtifactInspection) -> Self {
        Self {
            sha256: value.sha256.clone(),
            size_bytes: value.size_bytes,
            path: value.path.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub name: String,
    pub source_revision: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub engine_version: String,
    pub generated_at: DateTime<Utc>,
    pub protocol_profile: u32,
    pub release: ReleaseInfo,
    pub current: ArtifactRecord,
    pub candidate: ArtifactRecord,
    pub analysis: AnalysisResult,
    pub simulations: Vec<SimulationEvidence>,
    pub limitations: Vec<String>,
}

pub fn build(config: &Config) -> Result<ReleaseManifest, ManifestError> {
    build_with_simulations(config, Vec::new())
}

pub fn build_with_simulations(
    config: &Config,
    mut simulations: Vec<SimulationEvidence>,
) -> Result<ReleaseManifest, ManifestError> {
    let current = inspect(&config.analysis.current_wasm, ProtocolProfile::Protocol28)
        .map_err(|e| ManifestError::Inspect(e.to_string()))?;
    let candidate = inspect(&config.analysis.candidate_wasm, ProtocolProfile::Protocol28)
        .map_err(|e| ManifestError::Inspect(e.to_string()))?;
    if current.sha256 == candidate.sha256 {
        return Err(ManifestError::Config(
            "analysis.current_wasm and analysis.candidate_wasm have identical hashes".into(),
        ));
    }
    let mut analysis = analyze(&current, &candidate);
    simulations.sort_by(|left, right| {
        (&left.scenario, &left.target).cmp(&(&right.scenario, &right.target))
    });
    if config.policy.require_simulation && !simulations.iter().any(|simulation| simulation.success)
    {
        analysis.findings.push(upgraderail_core::Finding::new(
            "SIM001",
            upgraderail_core::Severity::Blocking,
            "Required simulation is missing",
            "Policy requires runtime simulation, but no scenario was configured.",
        ));
        analysis.status = UpgradeStatus::from_findings(&analysis.findings);
    }
    Ok(ReleaseManifest {
        schema_version: 1,
        engine_version: env!("CARGO_PKG_VERSION").into(),
        generated_at: Utc::now(),
        protocol_profile: 28,
        release: ReleaseInfo {
            name: config.project.name.clone(),
            source_revision: config.project.source_revision.clone(),
        },
        current: (&current).into(),
        candidate: (&candidate).into(),
        analysis,
        simulations,
        limitations: vec![
            "Static WASM analysis cannot prove runtime authorization or storage compatibility."
                .into(),
        ],
    })
}

pub fn write(manifest: &ReleaseManifest, path: impl AsRef<Path>) -> Result<String, ManifestError> {
    let path = path.as_ref();
    let mut bytes =
        serde_json::to_vec_pretty(manifest).map_err(|e| ManifestError::Serialize(e.to_string()))?;
    bytes.push(b'\n');
    fs::write(path, &bytes).map_err(|source| ManifestError::Write {
        path: path.into(),
        source,
    })?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

pub fn hash_file(path: impl AsRef<Path>) -> Result<String, ManifestError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| ManifestError::Read {
        path: path.into(),
        source,
    })?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn verify_file(path: impl AsRef<Path>, expected: &str) -> Result<bool, ManifestError> {
    Ok(hash_file(path)?.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_bytes_are_hashed_and_tampering_fails() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"{}\n").unwrap();
        let hash = hash_file(file.path()).unwrap();
        assert!(verify_file(file.path(), &hash).unwrap());
        fs::write(file.path(), b"{} \n").unwrap();
        assert!(!verify_file(file.path(), &hash).unwrap());
    }

    #[test]
    fn configuration_rejects_duplicate_or_invalid_scenarios() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            r#"schema_version = 1
[project]
name = "test"
[analysis]
protocol_profile = 28
current_wasm = "a.wasm"
candidate_wasm = "b.wasm"
[[simulation]]
name = "repeat"
source_account = "GB6NGKUWJFXWAVE5K3UNLGTPTBGD3TDVOZAA3ITOBIMUR25SGMLGKRA6"
current_contract = "CCMC4WGOCRU34RYO4YK64QVDNOMJBS27SBHH42ARQ7NOCQPZMRZMSLR3"
candidate_contract = "CCMC4WGOCRU34RYO4YK64QVDNOMJBS27SBHH42ARQ7NOCQPZMRZMSLR3"
function = "get"
[simulation.network]
name = "testnet"
rpc_url = "https://example.test/rpc"
network_passphrase = "test"
[[simulation]]
name = "repeat"
source_account = "GB6NGKUWJFXWAVE5K3UNLGTPTBGD3TDVOZAA3ITOBIMUR25SGMLGKRA6"
current_contract = "CCMC4WGOCRU34RYO4YK64QVDNOMJBS27SBHH42ARQ7NOCQPZMRZMSLR3"
candidate_contract = "CCMC4WGOCRU34RYO4YK64QVDNOMJBS27SBHH42ARQ7NOCQPZMRZMSLR3"
function = "get"
[simulation.network]
name = "testnet"
rpc_url = "https://example.test/rpc"
network_passphrase = "test"
"#,
        )
        .unwrap();
        assert!(Config::load(file.path()).is_err());
    }

    #[test]
    fn configuration_rejects_unknown_fields_and_unsupported_schema() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            file.path(),
            r#"schema_version = 2
unexpected = true
[project]
name = "test"
[analysis]
protocol_profile = 28
current_wasm = "a.wasm"
candidate_wasm = "b.wasm"
"#,
        )
        .unwrap();
        assert!(Config::load(file.path()).is_err());
    }
}

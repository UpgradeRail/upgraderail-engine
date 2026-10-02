mod analyzer;
mod rules;

use serde::{Deserialize, Serialize};
use upgraderail_core::UpgradeStatus;

pub use analyzer::analyze;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub status: UpgradeStatus,
    pub findings: Vec<upgraderail_core::Finding>,
    pub storage_compatibility: String,
    pub authorization_behavior: String,
}

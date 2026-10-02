use crate::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpgradeStatus {
    Blocked,
    ReadyWithWarnings,
    Ready,
}

impl UpgradeStatus {
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        if findings.iter().any(|f| f.severity == Severity::Blocking) {
            Self::Blocked
        } else if findings.iter().any(|f| f.severity == Severity::Warning) {
            Self::ReadyWithWarnings
        } else {
            Self::Ready
        }
    }
}

impl fmt::Display for UpgradeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Blocked => "BLOCKED",
                Self::ReadyWithWarnings => "READY_WITH_WARNINGS",
                Self::Ready => "READY",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_is_derived_from_findings() {
        assert_eq!(UpgradeStatus::from_findings(&[]), UpgradeStatus::Ready);
        assert_eq!(
            UpgradeStatus::from_findings(&[Finding::new("X", Severity::Warning, "x", "x")]),
            UpgradeStatus::ReadyWithWarnings
        );
        assert_eq!(
            UpgradeStatus::from_findings(&[Finding::new("X", Severity::Blocking, "x", "x")]),
            UpgradeStatus::Blocked
        );
    }
}

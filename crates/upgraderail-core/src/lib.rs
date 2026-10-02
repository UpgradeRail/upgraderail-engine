use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Blocking,
    Warning,
    Info,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(code: &str, severity: Severity, title: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            title: title.into(),
            message: message.into(),
            evidence: Vec::new(),
        }
    }
}

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProtocolProfile {
    #[default]
    #[serde(rename = "28")]
    Protocol28,
}

impl fmt::Display for ProtocolProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "28")
    }
}

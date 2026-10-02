use crate::Evidence;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Blocking,
    Warning,
    Info,
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
    #[must_use]
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

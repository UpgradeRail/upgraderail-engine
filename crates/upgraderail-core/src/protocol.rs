use serde::{Deserialize, Serialize};
use std::fmt;

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

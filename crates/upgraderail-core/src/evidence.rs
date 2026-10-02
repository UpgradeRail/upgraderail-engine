use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub reference: String,
}

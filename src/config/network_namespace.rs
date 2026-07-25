//! Network namespace configuration (sing-box 1.14.0-alpha.43+).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A network namespace. Keeping the option payload open lets Turntable
/// round-trip platform-specific additions without deleting them.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NetworkNamespace {
    Default(NetworkNamespaceOptions),
    Unshare(NetworkNamespaceOptions),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NetworkNamespaceOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(flatten)]
    pub options: HashMap<String, Value>,
}

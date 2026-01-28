use serde::{Deserialize, Serialize};

use crate::config::outbound::Outbound;

// ============================================================================
// Subscription Types
// ============================================================================

/// Subscription configuration for fetching proxy outbounds
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Subscription {
    /// Name/identifier for this subscription
    pub name: String,

    /// URL to fetch the subscription from
    pub url: String,

    /// Optional filter to remove outbounds by index (0-based).
    /// E.g., `filter = [0, 1, 2]` removes the first, second, and third outbounds.
    #[serde(default)]
    pub filter: Vec<usize>,
}

// ============================================================================
// Sing-box Subscription Format
// ============================================================================

/// Sing-box format subscription response
/// Contains only outbounds array
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingBoxSubscription {
    /// Outbound configurations from subscription
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
}

impl SingBoxSubscription {
    /// Create a new empty subscription
    pub fn new() -> Self {
        Self {
            outbounds: Vec::new(),
        }
    }

    /// Create a subscription with the given outbounds
    pub fn with_outbounds(outbounds: Vec<Outbound>) -> Self {
        Self { outbounds }
    }
}

impl Default for SingBoxSubscription {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_config() {
        let toml_str = r#"
            name = "MyProvider"
            url = "https://example.com/sub"
            filter = [0, 1, 2]
        "#;

        let sub: Subscription = toml::from_str(toml_str).unwrap();
        assert_eq!(sub.name, "MyProvider");
        assert_eq!(sub.url, "https://example.com/sub");
        assert_eq!(sub.filter, vec![0, 1, 2]);
    }

    #[test]
    fn test_parse_subscription_config_no_filter() {
        let toml_str = r#"
            name = "MyProvider"
            url = "https://example.com/sub"
        "#;

        let sub: Subscription = toml::from_str(toml_str).unwrap();
        assert_eq!(sub.name, "MyProvider");
        assert_eq!(sub.url, "https://example.com/sub");
        assert!(sub.filter.is_empty());
    }

    #[test]
    fn test_singbox_subscription_new() {
        let sub = SingBoxSubscription::new();
        assert!(sub.outbounds.is_empty());
    }

    #[test]
    fn test_singbox_subscription_default() {
        let sub = SingBoxSubscription::default();
        assert!(sub.outbounds.is_empty());
    }

    #[test]
    fn test_parse_singbox_subscription_json() {
        let json = r#"{"outbounds": []}"#;
        let sub: SingBoxSubscription = serde_json::from_str(json).unwrap();
        assert!(sub.outbounds.is_empty());
    }

    #[test]
    fn test_parse_singbox_subscription_empty_json() {
        let json = r#"{}"#;
        let sub: SingBoxSubscription = serde_json::from_str(json).unwrap();
        assert!(sub.outbounds.is_empty());
    }
}

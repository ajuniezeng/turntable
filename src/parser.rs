//! Subscription and Protocol Parsing Module
//!
//! This module provides functionality for:
//! - Detecting subscription content types (Sing-box JSON, Base64 URI list, Clash YAML)
//! - Decoding content (handling Base64 encoding with various line break scenarios)
//! - Parsing protocol URIs (ss://, vmess://, vless://, trojan://, hysteria2://, tuic://)
//! - Dynamic dispatch to appropriate parsers based on detected type

pub mod base64;
pub mod detection;
pub mod protocols;

// Re-export commonly used types and functions
pub use base64::{decode_base64, decode_subscription_content};
pub use detection::{SubscriptionType, detect_subscription_type};
pub use protocols::{
    Hysteria2Parser, ProtocolParser, ProtocolRegistry, ShadowsocksParser, TrojanParser, TuicParser,
    VLessParser, VMessParser,
};

use anyhow::{Result, bail};
use serde::Deserialize;
use tracing::debug;

use crate::config::outbound::Outbound;

// ============================================================================
// Subscription Parser Trait
// ============================================================================

/// Trait for parsing different subscription formats
pub trait SubscriptionParser: Send + Sync {
    /// Returns the subscription type this parser handles
    fn subscription_type(&self) -> SubscriptionType;

    /// Parses subscription content into a list of outbounds
    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>>;
}

/// Parser for Sing-box JSON subscriptions
pub struct SingBoxJsonParser;

impl SubscriptionParser for SingBoxJsonParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::SingBoxJson
    }

    fn parse(&self, content: &str, _registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        #[derive(Deserialize)]
        struct SingBoxSubscription {
            #[serde(default)]
            outbounds: Vec<Outbound>,
        }

        debug!("Parsing Sing-box JSON subscription");
        let subscription: SingBoxSubscription = serde_json::from_str(content)
            .map_err(|e| anyhow::anyhow!("Failed to parse Sing-box JSON subscription: {}", e))?;

        debug!(
            "Sing-box JSON parsing complete: {} outbounds found",
            subscription.outbounds.len()
        );

        Ok(subscription.outbounds)
    }
}

/// Parser for URI list subscriptions (both plain and Base64 encoded)
pub struct UriListParser;

impl SubscriptionParser for UriListParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::PlainUriList
    }

    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        debug!("Parsing plain URI list subscription");
        let outbounds = registry.parse_uri_list_lossy(content);
        debug!(
            "Plain URI list parsing complete: {} outbounds",
            outbounds.len()
        );
        Ok(outbounds)
    }
}

/// Parser for Base64 encoded URI lists
pub struct Base64UriListParser;

impl SubscriptionParser for Base64UriListParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::Base64UriList
    }

    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        debug!("Parsing Base64 encoded URI list subscription");
        let decoded = decode_subscription_content(content)?;
        debug!("Base64 decoded content length: {} bytes", decoded.len());
        let outbounds = registry.parse_uri_list_lossy(&decoded);
        debug!(
            "Base64 URI list parsing complete: {} outbounds",
            outbounds.len()
        );
        Ok(outbounds)
    }
}

// ============================================================================
// Unified Subscription Parsing
// ============================================================================

/// Parses subscription content with automatic type detection
pub fn parse_subscription(content: &str) -> Result<Vec<Outbound>> {
    let registry = ProtocolRegistry::with_builtin_parsers();
    parse_subscription_with_registry(content, &registry)
}

/// Parses subscription content using a custom registry
pub fn parse_subscription_with_registry(
    content: &str,
    registry: &ProtocolRegistry,
) -> Result<Vec<Outbound>> {
    let subscription_type = detect_subscription_type(content);
    debug!("Detected subscription type: {}", subscription_type);

    match subscription_type {
        SubscriptionType::SingBoxJson => SingBoxJsonParser.parse(content, registry),
        SubscriptionType::PlainUriList => UriListParser.parse(content, registry),
        SubscriptionType::Base64UriList => Base64UriListParser.parse(content, registry),
        SubscriptionType::ClashYaml => {
            bail!("Clash YAML format is not yet supported")
        }
        SubscriptionType::Unknown => {
            bail!("Unable to detect subscription format")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_subscription_singbox_json() {
        let content = r#"{"outbounds": []}"#;
        let result = parse_subscription(content).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_subscription_singbox_json_with_outbounds() {
        let content = r#"{"outbounds": [{"type": "direct", "tag": "direct"}]}"#;
        let result = parse_subscription(content).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_subscription_plain_uri_list() {
        // Single valid SS URI
        let content = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#test";
        let result = parse_subscription(content).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_parse_subscription_clash_yaml_unsupported() {
        let content = "proxies:\n  - name: test";
        let result = parse_subscription(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subscription_unknown_format() {
        let content = "this is not a valid subscription format";
        let result = parse_subscription(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_singbox_json_parser() {
        let parser = SingBoxJsonParser;
        let registry = ProtocolRegistry::new();
        let content = r#"{"outbounds": [{"type": "direct", "tag": "direct"}]}"#;
        let result = parser.parse(content, &registry).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_uri_list_parser() {
        let parser = UriListParser;
        let registry = ProtocolRegistry::with_builtin_parsers();
        let content = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#test";
        let result = parser.parse(content, &registry).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_subscription_parser_trait() {
        let parser = SingBoxJsonParser;
        assert_eq!(parser.subscription_type(), SubscriptionType::SingBoxJson);

        let parser = UriListParser;
        assert_eq!(parser.subscription_type(), SubscriptionType::PlainUriList);

        let parser = Base64UriListParser;
        assert_eq!(parser.subscription_type(), SubscriptionType::Base64UriList);
    }
}

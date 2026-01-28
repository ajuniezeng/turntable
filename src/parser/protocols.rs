//! Protocol parsers module
//!
//! This module contains parsers for various proxy protocol URI formats.
//! Each parser implements the `ProtocolParser` trait to provide a consistent
//! interface for parsing proxy URIs into sing-box outbound configurations.

mod hysteria2;
mod shadowsocks;
mod trojan;
mod tuic;
mod vless;
mod vmess;

pub use hysteria2::Hysteria2Parser;
pub use shadowsocks::ShadowsocksParser;
pub use trojan::TrojanParser;
pub use tuic::TuicParser;
pub use vless::VLessParser;
pub use vmess::VMessParser;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tracing::debug;

use crate::config::outbound::Outbound;

// ============================================================================
// Protocol Parser Trait
// ============================================================================

/// Trait for parsing individual protocol URIs
pub trait ProtocolParser: Send + Sync {
    /// Returns the protocol scheme this parser handles (e.g., "ss", "vmess")
    fn scheme(&self) -> &str;

    /// Parses a URI string into an Outbound configuration
    fn parse(&self, uri: &str) -> Result<Outbound>;

    /// Checks if this parser can handle the given URI
    fn can_parse(&self, uri: &str) -> bool {
        uri.starts_with(&format!("{}://", self.scheme()))
    }
}

// ============================================================================
// Protocol Registry
// ============================================================================

/// Registry for protocol parsers with dynamic dispatch
#[derive(Default)]
pub struct ProtocolRegistry {
    parsers: HashMap<String, Arc<dyn ProtocolParser>>,
}

impl ProtocolRegistry {
    /// Creates a new empty registry
    pub fn new() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    /// Creates a registry with all built-in parsers registered
    pub fn with_builtin_parsers() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(ShadowsocksParser));
        registry.register(Arc::new(VMessParser));
        registry.register(Arc::new(VLessParser));
        registry.register(Arc::new(TrojanParser));
        registry.register(Arc::new(Hysteria2Parser::new("hysteria2")));
        registry.register(Arc::new(Hysteria2Parser::new("hy2")));
        registry.register(Arc::new(TuicParser));
        registry
    }

    /// Registers a protocol parser
    pub fn register(&mut self, parser: Arc<dyn ProtocolParser>) {
        self.parsers.insert(parser.scheme().to_string(), parser);
    }

    /// Gets a parser for the given scheme
    pub fn get(&self, scheme: &str) -> Option<&Arc<dyn ProtocolParser>> {
        self.parsers.get(scheme)
    }

    /// Parses a URI using the appropriate parser
    pub fn parse_uri(&self, uri: &str) -> Result<Outbound> {
        let scheme = extract_scheme(uri)?;
        debug!("Parsing URI with scheme '{}': {}", scheme, uri);

        let parser = self
            .parsers
            .get(scheme)
            .ok_or_else(|| anyhow!("No parser registered for scheme: {}", scheme))?;

        let result = parser.parse(uri);
        match &result {
            Ok(outbound) => {
                let tag = crate::transform::get_outbound_tag(outbound)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<no tag>".to_string());
                debug!("Successfully parsed {} URI -> outbound '{}'", scheme, tag);
            }
            Err(e) => {
                debug!("Failed to parse {} URI: {}", scheme, e);
            }
        }
        result
    }

    /// Parses multiple URIs from content (one per line)
    pub fn parse_uri_list(&self, content: &str) -> Vec<Result<Outbound>> {
        let lines: Vec<&str> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        debug!("Parsing {} URI lines from content", lines.len());

        lines.into_iter().map(|line| self.parse_uri(line)).collect()
    }

    /// Parses multiple URIs, collecting only successful results
    pub fn parse_uri_list_lossy(&self, content: &str) -> Vec<Outbound> {
        use tracing::warn;

        let results = self.parse_uri_list(content);
        let total = results.len();

        let outbounds: Vec<Outbound> = results
            .into_iter()
            .filter_map(|r| match r {
                Ok(outbound) => Some(outbound),
                Err(e) => {
                    warn!("Failed to parse URI: {}", e);
                    None
                }
            })
            .collect();

        let success = outbounds.len();
        let failed = total - success;
        debug!(
            "URI list parsing complete: {} total, {} successful, {} failed",
            total, success, failed
        );

        outbounds
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parses host:port string, handling IPv6 addresses in brackets
pub fn parse_host_port(hostport: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses: [::1]:8080
    if hostport.starts_with('[') {
        let bracket_end = hostport
            .find(']')
            .ok_or_else(|| anyhow!("Invalid IPv6 address: missing closing bracket"))?;

        let host = hostport[1..bracket_end].to_string();
        let port_str = hostport
            .get(bracket_end + 2..)
            .ok_or_else(|| anyhow!("Missing port after IPv6 address"))?;

        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("Invalid port number: {}", port_str))?;
        return Ok((host, port));
    }

    // Handle regular host:port
    let colon_pos = hostport
        .rfind(':')
        .ok_or_else(|| anyhow!("Invalid host:port format: missing colon"))?;

    let host = hostport[..colon_pos].to_string();
    let port: u16 = hostport[colon_pos + 1..]
        .parse()
        .map_err(|_| anyhow!("Invalid port number"))?;

    Ok((host, port))
}

/// Extracts the scheme from a URI
pub fn extract_scheme(uri: &str) -> Result<&str> {
    // First check that :// actually exists in the URI
    if !uri.contains("://") {
        anyhow::bail!("Invalid URI: missing scheme separator ://");
    }
    uri.split("://")
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Invalid URI: missing scheme"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_registry_new() {
        let registry = ProtocolRegistry::new();
        assert!(registry.parsers.is_empty());
    }

    #[test]
    fn test_protocol_registry_with_builtin_parsers() {
        let registry = ProtocolRegistry::with_builtin_parsers();
        assert!(registry.get("ss").is_some());
        assert!(registry.get("vmess").is_some());
        assert!(registry.get("vless").is_some());
        assert!(registry.get("trojan").is_some());
        assert!(registry.get("hysteria2").is_some());
        assert!(registry.get("hy2").is_some());
        assert!(registry.get("tuic").is_some());
    }

    #[test]
    fn test_extract_scheme_valid() {
        assert_eq!(extract_scheme("ss://abc").unwrap(), "ss");
        assert_eq!(extract_scheme("vmess://xyz").unwrap(), "vmess");
        assert_eq!(extract_scheme("https://example.com").unwrap(), "https");
    }

    #[test]
    fn test_extract_scheme_invalid() {
        assert!(extract_scheme("not-a-uri").is_err());
        assert!(extract_scheme("://missing").is_err());
        assert!(extract_scheme("").is_err());
    }

    #[test]
    fn test_parse_uri_unknown_scheme() {
        let registry = ProtocolRegistry::with_builtin_parsers();
        let result = registry.parse_uri("unknown://test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uri_list_filters_empty_lines() {
        let registry = ProtocolRegistry::new();
        let content = "\n\n# comment\n  \n";
        let results = registry.parse_uri_list(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_uri_list_filters_comments() {
        let registry = ProtocolRegistry::new();
        let content = "# This is a comment\n# Another comment";
        let results = registry.parse_uri_list(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_host_port_ipv4() {
        let (host, port) = parse_host_port("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6_full() {
        let (host, port) = parse_host_port("[2001:db8::1]:443").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_missing_port() {
        assert!(parse_host_port("example.com").is_err());
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        assert!(parse_host_port("example.com:invalid").is_err());
    }

    #[test]
    fn test_parse_host_port_ipv6_missing_bracket() {
        assert!(parse_host_port("[::1:8080").is_err());
    }
}

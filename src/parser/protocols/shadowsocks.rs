//! Shadowsocks protocol parser
//!
//! This module provides parsing for Shadowsocks (ss://) URIs.
//! Supports both SIP002 format and legacy format.

use anyhow::{Context, Result, anyhow};
use tracing::trace;

use crate::config::outbound::{Outbound, ShadowsocksOutbound};
use crate::config::shared::DialFields;
use crate::parser::base64::decode_base64;

use super::{ProtocolParser, parse_host_port};

// ============================================================================
// Shadowsocks Parser
// ============================================================================

/// Parser for Shadowsocks (ss://) URIs
///
/// Supports both SIP002 format and legacy format:
/// - SIP002: ss://BASE64(method:password)@host:port#tag
/// - SIP002 with userinfo: ss://method:password@host:port#tag
/// - Legacy: ss://BASE64(method:password@host:port)#tag
pub struct ShadowsocksParser;

impl ProtocolParser for ShadowsocksParser {
    fn scheme(&self) -> &str {
        "ss"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        let uri = uri.trim();
        trace!("Parsing Shadowsocks URI");

        // Remove the ss:// prefix
        let without_scheme = uri
            .strip_prefix("ss://")
            .ok_or_else(|| anyhow!("Invalid Shadowsocks URI: missing ss:// prefix"))?;

        // Extract fragment (tag) if present
        let (main_part, tag) = match without_scheme.rfind('#') {
            Some(pos) => {
                let tag = urlencoding::decode(&without_scheme[pos + 1..])
                    .unwrap_or_else(|_| without_scheme[pos + 1..].into())
                    .into_owned();
                (&without_scheme[..pos], Some(tag.clone()))
            }
            None => (without_scheme, None),
        };

        // Try to parse as SIP002 format first (has @ separator)
        if let Some(at_pos) = main_part.rfind('@') {
            trace!("Parsing as SIP002 format (found @ separator)");
            return self.parse_sip002(main_part, at_pos, tag);
        }

        // Try legacy format (entire content is Base64 encoded)
        trace!("Parsing as legacy Base64 format");
        self.parse_legacy(main_part, tag)
    }
}

impl ShadowsocksParser {
    /// Parses SIP002 format: BASE64(method:password)@host:port or method:password@host:port
    fn parse_sip002(
        &self,
        main_part: &str,
        at_pos: usize,
        tag: Option<String>,
    ) -> Result<Outbound> {
        let userinfo = &main_part[..at_pos];
        let hostport = &main_part[at_pos + 1..];

        // Parse host:port
        let (server, server_port) = parse_host_port(hostport)?;

        // Decode userinfo (might be Base64 or plain method:password)
        let (method, password) = self.parse_userinfo(userinfo)?;

        let final_tag = tag.unwrap_or_else(|| format!("{}:{}", server, server_port));

        Ok(Outbound::Shadowsocks(ShadowsocksOutbound {
            tag: Some(final_tag),
            server: Some(server),
            server_port: Some(server_port),
            method: Some(method),
            password: Some(password),
            plugin: None,
            plugin_opts: None,
            network: None,
            udp_over_tcp: None,
            multiplex: None,
            dial: DialFields::default(),
        }))
    }

    /// Parses legacy format: BASE64(method:password@host:port)
    fn parse_legacy(&self, main_part: &str, tag: Option<String>) -> Result<Outbound> {
        let decoded = decode_base64(main_part)
            .and_then(|b| String::from_utf8(b).context("Invalid UTF-8 in Shadowsocks URI"))
            .context("Failed to decode legacy Shadowsocks URI")?;

        // Parse decoded content: method:password@host:port
        let at_pos = decoded
            .rfind('@')
            .ok_or_else(|| anyhow!("Invalid legacy Shadowsocks format: missing @"))?;

        let userinfo = &decoded[..at_pos];
        let hostport = &decoded[at_pos + 1..];

        let (server, server_port) = parse_host_port(hostport)?;

        let colon_pos = userinfo.find(':').ok_or_else(|| {
            anyhow!("Invalid Shadowsocks userinfo: missing method:password separator")
        })?;

        let method = userinfo[..colon_pos].to_string();
        let password = userinfo[colon_pos + 1..].to_string();

        let final_tag = tag.unwrap_or_else(|| format!("{}:{}", server, server_port));

        Ok(Outbound::Shadowsocks(ShadowsocksOutbound {
            tag: Some(final_tag),
            server: Some(server),
            server_port: Some(server_port),
            method: Some(method),
            password: Some(password),
            plugin: None,
            plugin_opts: None,
            network: None,
            udp_over_tcp: None,
            multiplex: None,
            dial: DialFields::default(),
        }))
    }

    /// Parses userinfo which can be Base64(method:password) or method:password
    fn parse_userinfo(&self, userinfo: &str) -> Result<(String, String)> {
        // First try to decode as Base64
        if let Ok(decoded) = decode_base64(userinfo)
            && let Ok(decoded_str) = String::from_utf8(decoded)
            && let Some(colon_pos) = decoded_str.find(':')
        {
            let method = decoded_str[..colon_pos].to_string();
            let password = decoded_str[colon_pos + 1..].to_string();
            return Ok((method, password));
        }

        // Try as plain method:password (URL-decoded)
        let decoded_userinfo = urlencoding::decode(userinfo)
            .unwrap_or_else(|_| userinfo.into())
            .into_owned();

        let colon_pos = decoded_userinfo
            .find(':')
            .ok_or_else(|| anyhow!("Invalid Shadowsocks userinfo format"))?;

        let method = decoded_userinfo[..colon_pos].to_string();
        let password = decoded_userinfo[colon_pos + 1..].to_string();

        Ok((method, password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowsocks_sip002_base64_userinfo() {
        let parser = ShadowsocksParser;
        // aes-256-gcm:password in Base64
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#test";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.tag, Some("test".to_string()));
            assert_eq!(ss.server, Some("example.com".to_string()));
            assert_eq!(ss.server_port, Some(8388));
            assert_eq!(ss.method, Some("aes-256-gcm".to_string()));
            assert_eq!(ss.password, Some("password".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_legacy_format() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let parser = ShadowsocksParser;
        // Create legacy format: BASE64(method:password@host:port)
        let encoded = STANDARD.encode("aes-256-gcm:password@example.com:8388");
        let uri = format!("ss://{}#legacy-test", encoded);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.tag, Some("legacy-test".to_string()));
            assert_eq!(ss.server, Some("example.com".to_string()));
            assert_eq!(ss.server_port, Some(8388));
            assert_eq!(ss.method, Some("aes-256-gcm".to_string()));
            assert_eq!(ss.password, Some("password".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_without_tag() {
        let parser = ShadowsocksParser;
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.tag, Some("example.com:8388".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_url_encoded_tag() {
        let parser = ShadowsocksParser;
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert!(ss.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_ipv6_host() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let parser = ShadowsocksParser;
        let encoded = STANDARD.encode("aes-256-gcm:password");
        let uri = format!("ss://{}@[::1]:8388#ipv6-test", encoded);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.server, Some("::1".to_string()));
            assert_eq!(ss.server_port, Some(8388));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_invalid_uri() {
        let parser = ShadowsocksParser;
        assert!(parser.parse("ss://").is_err());
        assert!(parser.parse("ss://invalid").is_err());
        assert!(parser.parse("vmess://wrong-scheme").is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = ShadowsocksParser;
        assert_eq!(parser.scheme(), "ss");
    }

    #[test]
    fn test_can_parse() {
        let parser = ShadowsocksParser;
        assert!(parser.can_parse("ss://abc"));
        assert!(!parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }
}

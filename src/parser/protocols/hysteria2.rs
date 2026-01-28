//! Hysteria2 protocol parser
//!
//! This module provides parsing for Hysteria2 (hysteria2:// or hy2://) URIs.
//! Format: hysteria2://auth@host:port?params#tag

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use tracing::trace;
use url::Url;

use crate::config::outbound::{Hysteria2Obfs, Hysteria2Outbound, Outbound};
use crate::config::shared::{DialFields, OutboundTlsConfig};

use super::ProtocolParser;

// ============================================================================
// Hysteria2 Parser
// ============================================================================

/// Parser for Hysteria2 (hysteria2:// or hy2://) URIs
///
/// Format: hysteria2://auth@host:port?params#tag
pub struct Hysteria2Parser {
    scheme: &'static str,
}

impl Hysteria2Parser {
    pub fn new(scheme: &'static str) -> Self {
        Self { scheme }
    }
}

impl ProtocolParser for Hysteria2Parser {
    fn scheme(&self) -> &str {
        self.scheme
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing Hysteria2 URI (scheme: {})", self.scheme);
        let url = Url::parse(uri).map_err(|e| anyhow!("Failed to parse Hysteria2 URI: {}", e))?;

        let password = urlencoding::decode(url.username())
            .unwrap_or_else(|_| url.username().into())
            .into_owned();

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("Hysteria2 URI missing host"))?
            .to_string();

        let server_port = url
            .port()
            .ok_or_else(|| anyhow!("Hysteria2 URI missing port"))?;

        // Parse query parameters
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

        let tag = url
            .fragment()
            .map(|f| {
                urlencoding::decode(f)
                    .unwrap_or_else(|_| f.into())
                    .into_owned()
            })
            .unwrap_or_else(|| format!("{}:{}", server, server_port));

        // Build TLS config
        let tls = Some(OutboundTlsConfig {
            enabled: true,
            server_name: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            insecure: params
                .get("insecure")
                .map(|s| s == "1" || s == "true")
                .unwrap_or(false),
            ..Default::default()
        });

        // Build obfs config
        let obfs = params.get("obfs").and_then(|obfs_type| {
            if obfs_type.is_empty() || obfs_type == "none" {
                None
            } else {
                Some(Hysteria2Obfs {
                    obfs_type: Some(obfs_type.clone()),
                    password: params.get("obfs-password").cloned(),
                })
            }
        });

        Ok(Outbound::Hysteria2(Hysteria2Outbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            server_ports: Vec::new(),
            hop_interval: None,
            up_mbps: params.get("up").and_then(|s| s.parse().ok()),
            down_mbps: params.get("down").and_then(|s| s.parse().ok()),
            obfs,
            password: if password.is_empty() {
                None
            } else {
                Some(password)
            },
            network: None,
            tls,
            brutal_debug: false,
            dial: DialFields::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_basic() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?sni=example.com#test-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.tag, Some("test-node".to_string()));
            assert_eq!(hy2.server, Some("example.com".to_string()));
            assert_eq!(hy2.server_port, Some(443));
            assert_eq!(hy2.password, Some("password".to_string()));
            assert!(hy2.tls.is_some());
            let tls = hy2.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("example.com".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hy2_scheme() {
        let parser = Hysteria2Parser::new("hy2");
        let uri = "hy2://password@example.com:443#hy2-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.tag, Some("hy2-node".to_string()));
            assert_eq!(hy2.password, Some("password".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_with_obfs() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?obfs=salamander&obfs-password=obfs-secret#obfs-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.obfs.is_some());
            let obfs = hy2.obfs.unwrap();
            assert_eq!(obfs.obfs_type, Some("salamander".to_string()));
            assert_eq!(obfs.password, Some("obfs-secret".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_obfs_none() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?obfs=none#no-obfs-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.obfs.is_none());
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_with_bandwidth() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?up=100&down=500#bandwidth-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.up_mbps, Some(100));
            assert_eq!(hy2.down_mbps, Some(500));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_insecure() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?insecure=1#insecure-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.tls.is_some());
            let tls = hy2.tls.unwrap();
            assert!(tls.insecure);
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_insecure_true() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?insecure=true#insecure-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.tls.is_some());
            assert!(hy2.tls.unwrap().insecure);
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_with_alpn() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443?alpn=h3,h2#alpn-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.tls.is_some());
            let tls = hy2.tls.unwrap();
            assert_eq!(tls.alpn, vec!["h3", "h2"]);
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_no_password() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://@example.com:443#no-password-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.password.is_none());
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_no_tag() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            // Should use server:port as tag when fragment is missing
            assert_eq!(hy2.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_url_encoded_password() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://pass%40word%21@example.com:443#encoded-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.password, Some("pass@word!".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_url_encoded_tag() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert!(hy2.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hysteria2_missing_host() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_hysteria2_missing_port() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@example.com";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_hysteria2_invalid_uri() {
        let parser = Hysteria2Parser::new("hysteria2");
        assert!(parser.parse("hysteria2://").is_err());
        assert!(parser.parse("not-a-uri").is_err());
    }

    #[test]
    fn test_scheme_hysteria2() {
        let parser = Hysteria2Parser::new("hysteria2");
        assert_eq!(parser.scheme(), "hysteria2");
    }

    #[test]
    fn test_scheme_hy2() {
        let parser = Hysteria2Parser::new("hy2");
        assert_eq!(parser.scheme(), "hy2");
    }

    #[test]
    fn test_can_parse_hysteria2() {
        let parser = Hysteria2Parser::new("hysteria2");
        assert!(parser.can_parse("hysteria2://password@host:port"));
        assert!(!parser.can_parse("hy2://password@host:port"));
        assert!(!parser.can_parse("vmess://abc"));
    }

    #[test]
    fn test_can_parse_hy2() {
        let parser = Hysteria2Parser::new("hy2");
        assert!(parser.can_parse("hy2://password@host:port"));
        assert!(!parser.can_parse("hysteria2://password@host:port"));
        assert!(!parser.can_parse("vmess://abc"));
    }

    #[test]
    fn test_hysteria2_ipv6_host() {
        let parser = Hysteria2Parser::new("hysteria2");
        let uri = "hysteria2://password@[::1]:443#ipv6-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            // URL library returns IPv6 with brackets
            assert_eq!(hy2.server, Some("[::1]".to_string()));
            assert_eq!(hy2.server_port, Some(443));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }
}

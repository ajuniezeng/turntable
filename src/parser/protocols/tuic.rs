//! TUIC protocol parser
//!
//! This module provides parsing for TUIC (tuic://) URIs.
//! Format: tuic://uuid:password@host:port?params#tag

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use tracing::trace;
use url::Url;

use crate::config::outbound::{Outbound, TuicOutbound};
use crate::config::shared::{DialFields, OutboundTlsConfig};

use super::ProtocolParser;

// ============================================================================
// TUIC Parser
// ============================================================================

/// Parser for TUIC (tuic://) URIs
///
/// Format: tuic://uuid:password@host:port?params#tag
pub struct TuicParser;

impl ProtocolParser for TuicParser {
    fn scheme(&self) -> &str {
        "tuic"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing TUIC URI");
        let url = Url::parse(uri).map_err(|e| anyhow!("Failed to parse TUIC URI: {}", e))?;

        let uuid = url.username().to_string();
        if uuid.is_empty() {
            bail!("TUIC URI missing UUID");
        }

        let password = url.password().map(|p| {
            urlencoding::decode(p)
                .unwrap_or_else(|_| p.into())
                .into_owned()
        });

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("TUIC URI missing host"))?
            .to_string();

        let server_port = url.port().ok_or_else(|| anyhow!("TUIC URI missing port"))?;

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
            ..Default::default()
        });

        Ok(Outbound::Tuic(TuicOutbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            uuid: Some(uuid),
            password,
            congestion_control: params.get("congestion_control").cloned(),
            udp_relay_mode: params.get("udp_relay_mode").cloned(),
            udp_over_stream: params
                .get("udp_over_stream")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            zero_rtt_handshake: params
                .get("zero_rtt_handshake")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            heartbeat: params.get("heartbeat").cloned(),
            network: None,
            tls,
            dial: DialFields::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_basic() {
        let parser = TuicParser;
        let uri = "tuic://uuid-here:password@example.com:443?sni=example.com#test-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.tag, Some("test-node".to_string()));
            assert_eq!(tuic.server, Some("example.com".to_string()));
            assert_eq!(tuic.server_port, Some(443));
            assert_eq!(tuic.uuid, Some("uuid-here".to_string()));
            assert_eq!(tuic.password, Some("password".to_string()));
            assert!(tuic.tls.is_some());
            let tls = tuic.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("example.com".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_without_password() {
        let parser = TuicParser;
        let uri = "tuic://uuid-here@example.com:443#no-password-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.uuid, Some("uuid-here".to_string()));
            assert!(tuic.password.is_none());
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_congestion_control() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?congestion_control=bbr#cc-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.congestion_control, Some("bbr".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_udp_relay_mode() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?udp_relay_mode=native#udp-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.udp_relay_mode, Some("native".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_udp_over_stream() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?udp_over_stream=true#udp-stream-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert!(tuic.udp_over_stream);
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_udp_over_stream_numeric() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?udp_over_stream=1#udp-stream-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert!(tuic.udp_over_stream);
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_zero_rtt() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?zero_rtt_handshake=true#zero-rtt-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert!(tuic.zero_rtt_handshake);
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_heartbeat() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?heartbeat=10s#heartbeat-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.heartbeat, Some("10s".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_with_alpn() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?alpn=h3,h2#alpn-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert!(tuic.tls.is_some());
            let tls = tuic.tls.unwrap();
            assert_eq!(tls.alpn, vec!["h3", "h2"]);
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_no_tag() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            // Should use server:port as tag when fragment is missing
            assert_eq!(tuic.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_url_encoded_password() {
        let parser = TuicParser;
        let uri = "tuic://uuid:pass%40word%21@example.com:443#encoded-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.password, Some("pass@word!".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_url_encoded_tag() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert!(tuic.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_missing_uuid() {
        let parser = TuicParser;
        let uri = "tuic://:password@example.com:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_tuic_missing_host() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_tuic_missing_port() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_tuic_invalid_uri() {
        let parser = TuicParser;
        assert!(parser.parse("tuic://").is_err());
        assert!(parser.parse("not-a-uri").is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = TuicParser;
        assert_eq!(parser.scheme(), "tuic");
    }

    #[test]
    fn test_can_parse() {
        let parser = TuicParser;
        assert!(parser.can_parse("tuic://uuid:password@host:port"));
        assert!(!parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }

    #[test]
    fn test_tuic_ipv6_host() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@[::1]:443#ipv6-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            // URL library returns IPv6 with brackets
            assert_eq!(tuic.server, Some("[::1]".to_string()));
            assert_eq!(tuic.server_port, Some(443));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    #[test]
    fn test_tuic_full_config() {
        let parser = TuicParser;
        let uri = "tuic://uuid:password@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&udp_over_stream=true&zero_rtt_handshake=true&heartbeat=10s#full-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.tag, Some("full-node".to_string()));
            assert_eq!(tuic.uuid, Some("uuid".to_string()));
            assert_eq!(tuic.password, Some("password".to_string()));
            assert_eq!(tuic.congestion_control, Some("bbr".to_string()));
            assert_eq!(tuic.udp_relay_mode, Some("native".to_string()));
            assert!(tuic.udp_over_stream);
            assert!(tuic.zero_rtt_handshake);
            assert_eq!(tuic.heartbeat, Some("10s".to_string()));
            assert!(tuic.tls.is_some());
            let tls = tuic.tls.unwrap();
            assert_eq!(tls.server_name, Some("example.com".to_string()));
            assert_eq!(tls.alpn, vec!["h3"]);
        } else {
            panic!("Expected TUIC outbound");
        }
    }
}

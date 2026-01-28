//! AnyTLS protocol parser
//!
//! This module provides parsing for AnyTLS (anytls://) URIs.
//! Format: anytls://[password@]host[:port]/?[key=value]&[key=value]...#tag

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use tracing::trace;
use url::Url;

use crate::config::outbound::{AnyTlsOutbound, Outbound};
use crate::config::shared::{DialFields, OutboundTlsConfig};

use super::ProtocolParser;

// ============================================================================
// AnyTLS Parser
// ============================================================================

/// Parser for AnyTLS (anytls://) URIs
///
/// Format: anytls://[password@]host[:port]/?[key=value]&[key=value]...#tag
///
/// Supported query parameters:
/// - `sni`: Server Name Indication for TLS
/// - `insecure`: Skip TLS certificate verification (1 = true)
/// - `alpn`: ALPN protocols (comma-separated)
pub struct AnyTlsParser;

impl ProtocolParser for AnyTlsParser {
    fn scheme(&self) -> &str {
        "anytls"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing AnyTLS URI");
        let url = Url::parse(uri).map_err(|e| anyhow!("Failed to parse AnyTLS URI: {}", e))?;

        // Password is in the username field
        let password = urlencoding::decode(url.username())
            .unwrap_or_else(|_| url.username().into())
            .into_owned();

        if password.is_empty() {
            bail!("AnyTLS URI missing password");
        }

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("AnyTLS URI missing host"))?
            .to_string();

        // Port is optional, default to 443 for TLS
        let server_port = url.port().unwrap_or(443);

        // Parse query parameters
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

        // Tag from fragment, or generate from server:port
        let tag = url
            .fragment()
            .map(|f| {
                urlencoding::decode(f)
                    .unwrap_or_else(|_| f.into())
                    .into_owned()
            })
            .unwrap_or_else(|| format!("{}:{}", server, server_port));

        // Build TLS configuration (AnyTLS always uses TLS)
        let tls = Some(OutboundTlsConfig {
            enabled: true,
            server_name: params.get("sni").cloned(),
            insecure: params
                .get("insecure")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            ..Default::default()
        });

        Ok(Outbound::AnyTls(AnyTlsOutbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            password: Some(password),
            tls,
            dial: DialFields::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anytls_basic() {
        let parser = AnyTlsParser;
        let uri = "anytls://letmein@example.com/?sni=real.example.com";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert_eq!(anytls.tag, Some("example.com:443".to_string()));
            assert_eq!(anytls.server, Some("example.com".to_string()));
            assert_eq!(anytls.server_port, Some(443));
            assert_eq!(anytls.password, Some("letmein".to_string()));
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("real.example.com".to_string()));
            assert!(!tls.insecure);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_with_insecure() {
        let parser = AnyTlsParser;
        let uri = "anytls://letmein@example.com/?sni=127.0.0.1&insecure=1";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("127.0.0.1".to_string()));
            assert!(tls.insecure);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_ipv6() {
        let parser = AnyTlsParser;
        let uri = "anytls://0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a@[2409:8a71:6a00:1953::615]:8964/?insecure=1";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            // URL library returns IPv6 with brackets
            assert_eq!(
                anytls.server,
                Some("[2409:8a71:6a00:1953::615]".to_string())
            );
            assert_eq!(anytls.server_port, Some(8964));
            assert_eq!(
                anytls.password,
                Some("0fdf77d7-d4ba-455e-9ed9-a98dd6d5489a".to_string())
            );
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(tls.insecure);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_with_tag() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com:8443/?sni=example.com#my-server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert_eq!(anytls.tag, Some("my-server".to_string()));
            assert_eq!(anytls.server_port, Some(8443));
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_with_alpn() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/?alpn=h2,http/1.1";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_default_port() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert_eq!(anytls.server_port, Some(443));
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_url_encoded_password() {
        let parser = AnyTlsParser;
        let uri = "anytls://pass%40word%21@example.com/";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert_eq!(anytls.password, Some("pass@word!".to_string()));
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_url_encoded_tag() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_insecure_true_string() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/?insecure=true";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(tls.insecure);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_insecure_false() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/?insecure=0";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(!tls.insecure);
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_missing_password() {
        let parser = AnyTlsParser;
        let uri = "anytls://@example.com/";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_anytls_missing_host() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@/";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_anytls_invalid_uri() {
        let parser = AnyTlsParser;
        assert!(parser.parse("anytls://").is_err());
        assert!(parser.parse("not-a-uri").is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = AnyTlsParser;
        assert_eq!(parser.scheme(), "anytls");
    }

    #[test]
    fn test_can_parse() {
        let parser = AnyTlsParser;
        assert!(parser.can_parse("anytls://password@host/"));
        assert!(!parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }

    #[test]
    fn test_anytls_no_query_params() {
        let parser = AnyTlsParser;
        let uri = "anytls://password@example.com/";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert!(anytls.tls.is_some());
            let tls = anytls.tls.unwrap();
            assert!(tls.enabled);
            assert!(tls.server_name.is_none());
            assert!(!tls.insecure);
            assert!(tls.alpn.is_empty());
        } else {
            panic!("Expected AnyTls outbound");
        }
    }

    #[test]
    fn test_anytls_uuid_password() {
        let parser = AnyTlsParser;
        let uri = "anytls://550e8400-e29b-41d4-a716-446655440000@example.com:443/";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::AnyTls(anytls) = outbound {
            assert_eq!(
                anytls.password,
                Some("550e8400-e29b-41d4-a716-446655440000".to_string())
            );
        } else {
            panic!("Expected AnyTls outbound");
        }
    }
}

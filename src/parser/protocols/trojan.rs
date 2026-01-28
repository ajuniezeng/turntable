//! Trojan protocol parser
//!
//! This module provides parsing for Trojan (trojan://) URIs.
//! Format: trojan://password@host:port?params#tag

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use tracing::trace;
use url::Url;

use crate::config::outbound::{
    GrpcTransport, Outbound, TrojanOutbound, V2RayTransport, WebSocketTransport,
};
use crate::config::shared::{DialFields, OutboundTlsConfig, UtlsConfig};

use super::ProtocolParser;

// ============================================================================
// Trojan Parser
// ============================================================================

/// Parser for Trojan (trojan://) URIs
///
/// Format: trojan://password@host:port?params#tag
pub struct TrojanParser;

impl ProtocolParser for TrojanParser {
    fn scheme(&self) -> &str {
        "trojan"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing Trojan URI");
        let url = Url::parse(uri).map_err(|e| anyhow!("Failed to parse Trojan URI: {}", e))?;

        let password = urlencoding::decode(url.username())
            .unwrap_or_else(|_| url.username().into())
            .into_owned();

        if password.is_empty() {
            bail!("Trojan URI missing password");
        }

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("Trojan URI missing host"))?
            .to_string();

        let server_port = url
            .port()
            .ok_or_else(|| anyhow!("Trojan URI missing port"))?;

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

        // Trojan typically uses TLS
        let security = params.get("security").map(|s| s.as_str()).unwrap_or("tls");
        let tls = if security != "none" {
            Some(OutboundTlsConfig {
                enabled: true,
                server_name: params.get("sni").cloned(),
                alpn: params
                    .get("alpn")
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                utls: params.get("fp").map(|fp| UtlsConfig {
                    enabled: true,
                    fingerprint: Some(fp.clone()),
                }),
                ..Default::default()
            })
        } else {
            None
        };

        // Build transport
        let transport = self.build_transport(&params);

        Ok(Outbound::Trojan(TrojanOutbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            password: Some(password),
            network: None,
            tls,
            multiplex: None,
            transport,
            dial: DialFields::default(),
        }))
    }
}

impl TrojanParser {
    fn build_transport(&self, params: &HashMap<String, String>) -> Option<V2RayTransport> {
        match params.get("type").map(|s| s.as_str()) {
            Some("ws") | Some("websocket") => {
                let mut headers = HashMap::new();
                if let Some(host) = params.get("host")
                    && !host.is_empty()
                {
                    headers.insert("Host".to_string(), host.clone());
                }

                Some(V2RayTransport::WebSocket(WebSocketTransport {
                    path: params.get("path").cloned(),
                    headers,
                    max_early_data: 0,
                    early_data_header_name: None,
                }))
            }
            Some("grpc") => Some(V2RayTransport::Grpc(GrpcTransport {
                service_name: params.get("serviceName").cloned(),
                idle_timeout: None,
                ping_timeout: None,
                permit_without_stream: false,
            })),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_basic() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443?sni=example.com#test-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert_eq!(trojan.tag, Some("test-node".to_string()));
            assert_eq!(trojan.server, Some("example.com".to_string()));
            assert_eq!(trojan.server_port, Some(443));
            assert_eq!(trojan.password, Some("password".to_string()));
            assert!(trojan.tls.is_some());
            let tls = trojan.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("example.com".to_string()));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_with_websocket() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443?type=ws&path=/ws&host=ws.example.com#ws-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.transport.is_some());
            if let Some(V2RayTransport::WebSocket(ws)) = trojan.transport {
                assert_eq!(ws.path, Some("/ws".to_string()));
                assert_eq!(ws.headers.get("Host"), Some(&"ws.example.com".to_string()));
            } else {
                panic!("Expected WebSocket transport");
            }
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_with_grpc() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443?type=grpc&serviceName=myservice#grpc-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.transport.is_some());
            if let Some(V2RayTransport::Grpc(grpc)) = trojan.transport {
                assert_eq!(grpc.service_name, Some("myservice".to_string()));
            } else {
                panic!("Expected gRPC transport");
            }
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_no_tls() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:8080?security=none#no-tls-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.tls.is_none());
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_with_fingerprint() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443?fp=chrome&sni=example.com#fp-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.tls.is_some());
            let tls = trojan.tls.unwrap();
            assert!(tls.utls.is_some());
            assert_eq!(tls.utls.unwrap().fingerprint, Some("chrome".to_string()));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_with_alpn() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443?alpn=h2,http/1.1#alpn-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.tls.is_some());
            let tls = trojan.tls.unwrap();
            assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_no_tag() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            // Should use server:port as tag when fragment is missing
            assert_eq!(trojan.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_url_encoded_password() {
        let parser = TrojanParser;
        let uri = "trojan://pass%40word%21@example.com:443#encoded-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert_eq!(trojan.password, Some("pass@word!".to_string()));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_url_encoded_tag() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_missing_password() {
        let parser = TrojanParser;
        let uri = "trojan://@example.com:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_trojan_missing_host() {
        let parser = TrojanParser;
        let uri = "trojan://password@:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_trojan_missing_port() {
        let parser = TrojanParser;
        let uri = "trojan://password@example.com";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_trojan_invalid_uri() {
        let parser = TrojanParser;
        assert!(parser.parse("trojan://").is_err());
        assert!(parser.parse("not-a-uri").is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = TrojanParser;
        assert_eq!(parser.scheme(), "trojan");
    }

    #[test]
    fn test_can_parse() {
        let parser = TrojanParser;
        assert!(parser.can_parse("trojan://password@host:port"));
        assert!(!parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }

    #[test]
    fn test_trojan_ipv6_host() {
        let parser = TrojanParser;
        let uri = "trojan://password@[::1]:443#ipv6-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            // URL library returns IPv6 with brackets
            assert_eq!(trojan.server, Some("[::1]".to_string()));
            assert_eq!(trojan.server_port, Some(443));
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    #[test]
    fn test_trojan_default_tls_enabled() {
        let parser = TrojanParser;
        // Without security param, TLS should be enabled by default
        let uri = "trojan://password@example.com:443#default-tls";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert!(trojan.tls.is_some());
            assert!(trojan.tls.unwrap().enabled);
        } else {
            panic!("Expected Trojan outbound");
        }
    }
}

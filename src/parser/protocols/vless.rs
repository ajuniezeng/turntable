//! VLESS protocol parser
//!
//! This module provides parsing for VLESS (vless://) URIs.
//! Format: vless://uuid@host:port?params#tag

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use tracing::trace;
use url::Url;

use crate::config::outbound::{
    GrpcTransport, Outbound, V2RayTransport, VLessOutbound, WebSocketTransport,
};
use crate::config::shared::{DialFields, OutboundRealityConfig, OutboundTlsConfig, UtlsConfig};

use super::ProtocolParser;

// ============================================================================
// VLESS Parser
// ============================================================================

/// Parser for VLESS (vless://) URIs
///
/// Format: vless://uuid@host:port?params#tag
pub struct VLessParser;

impl ProtocolParser for VLessParser {
    fn scheme(&self) -> &str {
        "vless"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing VLESS URI");
        let url = Url::parse(uri).map_err(|e| anyhow!("Failed to parse VLESS URI: {}", e))?;

        let uuid = url.username().to_string();
        if uuid.is_empty() {
            bail!("VLESS URI missing UUID");
        }

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("VLESS URI missing host"))?
            .to_string();

        let server_port = url
            .port()
            .ok_or_else(|| anyhow!("VLESS URI missing port"))?;

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
        let security = params.get("security").map(|s| s.as_str()).unwrap_or("");
        let tls = if security == "tls" || security == "reality" {
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
                reality: if security == "reality" {
                    Some(OutboundRealityConfig {
                        enabled: true,
                        public_key: params.get("pbk").cloned(),
                        short_id: params.get("sid").cloned(),
                    })
                } else {
                    None
                },
                ..Default::default()
            })
        } else {
            None
        };

        // Build transport
        let transport = self.build_transport(&params);

        // Flow control
        let flow = params.get("flow").cloned();

        Ok(Outbound::VLess(VLessOutbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            uuid: Some(uuid),
            flow,
            network: None,
            tls,
            packet_encoding: params.get("packetEncoding").cloned(),
            multiplex: None,
            transport,
            dial: DialFields::default(),
        }))
    }
}

impl VLessParser {
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
    fn test_vless_basic() {
        let parser = VLessParser;
        let uri = "vless://uuid-here@example.com:443?security=tls&sni=example.com#test-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert_eq!(vless.tag, Some("test-node".to_string()));
            assert_eq!(vless.server, Some("example.com".to_string()));
            assert_eq!(vless.server_port, Some(443));
            assert_eq!(vless.uuid, Some("uuid-here".to_string()));
            assert!(vless.tls.is_some());
            let tls = vless.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.server_name, Some("example.com".to_string()));
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_with_reality() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443?security=reality&pbk=public-key&sid=short-id&fp=chrome&sni=example.com#reality-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert_eq!(vless.tag, Some("reality-node".to_string()));
            assert!(vless.tls.is_some());
            let tls = vless.tls.unwrap();
            assert!(tls.reality.is_some());
            let reality = tls.reality.unwrap();
            assert!(reality.enabled);
            assert_eq!(reality.public_key, Some("public-key".to_string()));
            assert_eq!(reality.short_id, Some("short-id".to_string()));
            assert!(tls.utls.is_some());
            assert_eq!(tls.utls.unwrap().fingerprint, Some("chrome".to_string()));
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_with_websocket() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443?type=ws&path=/ws&host=ws.example.com&security=tls#ws-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.transport.is_some());
            if let Some(V2RayTransport::WebSocket(ws)) = vless.transport {
                assert_eq!(ws.path, Some("/ws".to_string()));
                assert_eq!(ws.headers.get("Host"), Some(&"ws.example.com".to_string()));
            } else {
                panic!("Expected WebSocket transport");
            }
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_with_grpc() {
        let parser = VLessParser;
        let uri =
            "vless://uuid@example.com:443?type=grpc&serviceName=myservice&security=tls#grpc-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.transport.is_some());
            if let Some(V2RayTransport::Grpc(grpc)) = vless.transport {
                assert_eq!(grpc.service_name, Some("myservice".to_string()));
            } else {
                panic!("Expected gRPC transport");
            }
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_with_flow() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443?flow=xtls-rprx-vision&security=tls#flow-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert_eq!(vless.flow, Some("xtls-rprx-vision".to_string()));
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_no_security() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:8080#plain-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.tls.is_none());
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_no_tag() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            // Should use server:port as tag when fragment is missing
            assert_eq!(vless.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_url_encoded_tag() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20US%20Server";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.tag.as_ref().unwrap().contains("US Server"));
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_with_alpn() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com:443?security=tls&alpn=h2,http/1.1#alpn-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.tls.is_some());
            let tls = vless.tls.unwrap();
            assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        } else {
            panic!("Expected VLess outbound");
        }
    }

    #[test]
    fn test_vless_missing_uuid() {
        let parser = VLessParser;
        let uri = "vless://@example.com:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_vless_missing_host() {
        let parser = VLessParser;
        let uri = "vless://uuid@:443";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_vless_missing_port() {
        let parser = VLessParser;
        let uri = "vless://uuid@example.com";
        assert!(parser.parse(uri).is_err());
    }

    #[test]
    fn test_vless_invalid_uri() {
        let parser = VLessParser;
        assert!(parser.parse("vless://").is_err());
        assert!(parser.parse("not-a-uri").is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = VLessParser;
        assert_eq!(parser.scheme(), "vless");
    }

    #[test]
    fn test_can_parse() {
        let parser = VLessParser;
        assert!(parser.can_parse("vless://uuid@host:port"));
        assert!(!parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }

    #[test]
    fn test_vless_ipv6_host() {
        let parser = VLessParser;
        let uri = "vless://uuid@[::1]:443#ipv6-node";
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            // URL library returns IPv6 with brackets
            assert_eq!(vless.server, Some("[::1]".to_string()));
            assert_eq!(vless.server_port, Some(443));
        } else {
            panic!("Expected VLess outbound");
        }
    }
}

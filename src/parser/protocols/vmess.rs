//! VMess protocol parser
//!
//! This module provides parsing for VMess (vmess://) URIs.
//! VMess URIs are typically Base64 encoded JSON containing connection details.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use tracing::trace;

use crate::config::outbound::{
    GrpcTransport, Outbound, V2RayTransport, VMessOutbound, WebSocketTransport,
};
use crate::config::shared::{DialFields, OutboundTlsConfig, UtlsConfig};
use crate::parser::base64::decode_base64;

use super::ProtocolParser;

// ============================================================================
// VMess Parser
// ============================================================================

/// Parser for VMess (vmess://) URIs
///
/// VMess URIs are typically Base64 encoded JSON:
/// vmess://BASE64({ "v": "2", "ps": "name", "add": "host", "port": 443, ... })
pub struct VMessParser;

/// VMess URI JSON structure
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct VMessJson {
    /// Version (usually "2")
    #[serde(default)]
    v: String,
    /// Remark/name
    #[serde(default)]
    ps: String,
    /// Server address
    add: String,
    /// Server port (can be string or number)
    #[serde(deserialize_with = "deserialize_port")]
    port: u16,
    /// UUID
    id: String,
    /// Alter ID (can be string or number)
    #[serde(default, deserialize_with = "deserialize_option_u32")]
    aid: Option<u32>,
    /// Security/encryption method
    #[serde(default)]
    scy: Option<String>,
    /// Network type (tcp, ws, etc.)
    #[serde(default)]
    net: Option<String>,
    /// TLS setting
    #[serde(default)]
    tls: Option<String>,
    /// SNI
    #[serde(default)]
    sni: Option<String>,
    /// ALPN
    #[serde(default)]
    alpn: Option<String>,
    /// Fingerprint
    #[serde(default)]
    fp: Option<String>,
    /// WebSocket host
    #[serde(default)]
    host: Option<String>,
    /// WebSocket path
    #[serde(default)]
    path: Option<String>,
    /// gRPC service name
    #[serde(default, rename = "serviceName")]
    service_name: Option<String>,
    /// Type (for various transports)
    #[serde(default, rename = "type")]
    transport_type: Option<String>,
}

impl ProtocolParser for VMessParser {
    fn scheme(&self) -> &str {
        "vmess"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        let uri = uri.trim();
        trace!("Parsing VMess URI");

        // Remove the vmess:// prefix
        let encoded = uri
            .strip_prefix("vmess://")
            .ok_or_else(|| anyhow!("Invalid VMess URI: missing vmess:// prefix"))?;

        // Decode Base64
        let decoded = decode_base64(encoded)
            .and_then(|b| String::from_utf8(b).context("Invalid UTF-8"))
            .context("Failed to decode VMess URI")?;

        trace!("Decoded VMess JSON: {}", decoded);

        // Parse JSON
        let json: VMessJson =
            serde_json::from_str(&decoded).context("Failed to parse VMess JSON")?;

        trace!(
            "VMess config: server={}:{}, uuid={}, net={:?}, tls={:?}",
            json.add, json.port, json.id, json.net, json.tls
        );

        // Build TLS config if needed
        let tls = if json.tls.as_deref() == Some("tls") {
            Some(OutboundTlsConfig {
                enabled: true,
                server_name: json.sni.clone(),
                alpn: json
                    .alpn
                    .as_ref()
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                utls: json.fp.as_ref().map(|fp| UtlsConfig {
                    enabled: true,
                    fingerprint: Some(fp.clone()),
                }),
                ..Default::default()
            })
        } else {
            None
        };

        // Build transport config
        let transport = self.build_transport(&json);

        let tag = if json.ps.is_empty() {
            format!("{}:{}", json.add, json.port)
        } else {
            json.ps
        };

        Ok(Outbound::VMess(VMessOutbound {
            tag: Some(tag),
            server: Some(json.add),
            server_port: Some(json.port),
            uuid: Some(json.id),
            security: json.scy.or_else(|| Some("auto".to_string())),
            alter_id: json.aid.unwrap_or(0),
            global_padding: false,
            authenticated_length: false,
            network: None,
            tls,
            packet_encoding: None,
            multiplex: None,
            transport,
            dial: DialFields::default(),
        }))
    }
}

impl VMessParser {
    fn build_transport(&self, json: &VMessJson) -> Option<V2RayTransport> {
        match json.net.as_deref() {
            Some("ws") | Some("websocket") => {
                let mut headers = HashMap::new();
                if let Some(host) = &json.host
                    && !host.is_empty()
                {
                    headers.insert("Host".to_string(), host.clone());
                }

                Some(V2RayTransport::WebSocket(WebSocketTransport {
                    path: json.path.clone(),
                    headers,
                    max_early_data: 0,
                    early_data_header_name: None,
                }))
            }
            Some("grpc") => Some(V2RayTransport::Grpc(GrpcTransport {
                service_name: json.service_name.clone(),
                idle_timeout: None,
                ping_timeout: None,
                permit_without_stream: false,
            })),
            _ => None,
        }
    }
}

// ============================================================================
// Deserialization Helpers
// ============================================================================

/// Custom deserializer for port (handles both string and number)
fn deserialize_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortValue {
        Number(u16),
        String(String),
    }

    match PortValue::deserialize(deserializer)? {
        PortValue::Number(n) => Ok(n),
        PortValue::String(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

/// Custom deserializer for optional u32 (handles both string and number)
fn deserialize_option_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U32Value {
        Number(u32),
        String(String),
        Null,
    }

    match Option::<U32Value>::deserialize(deserializer)? {
        Some(U32Value::Number(n)) => Ok(Some(n)),
        Some(U32Value::String(s)) if s.is_empty() => Ok(None),
        Some(U32Value::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
        Some(U32Value::Null) | None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    fn encode_vmess_json(json: &str) -> String {
        format!("vmess://{}", STANDARD.encode(json))
    }

    #[test]
    fn test_vmess_basic() {
        let parser = VMessParser;
        let json =
            r#"{"v":"2","ps":"test-node","add":"example.com","port":443,"id":"uuid-here","aid":0}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert_eq!(vmess.tag, Some("test-node".to_string()));
            assert_eq!(vmess.server, Some("example.com".to_string()));
            assert_eq!(vmess.server_port, Some(443));
            assert_eq!(vmess.uuid, Some("uuid-here".to_string()));
            assert_eq!(vmess.alter_id, 0);
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_with_websocket() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"ws-node","add":"example.com","port":"443","id":"uuid","aid":"0","net":"ws","path":"/ws","host":"ws.example.com","tls":"tls","sni":"example.com"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert_eq!(vmess.tag, Some("ws-node".to_string()));
            assert!(vmess.tls.is_some());
            assert!(vmess.transport.is_some());
            if let Some(V2RayTransport::WebSocket(ws)) = vmess.transport {
                assert_eq!(ws.path, Some("/ws".to_string()));
                assert_eq!(ws.headers.get("Host"), Some(&"ws.example.com".to_string()));
            } else {
                panic!("Expected WebSocket transport");
            }
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_with_grpc() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"grpc-node","add":"example.com","port":443,"id":"uuid","net":"grpc","serviceName":"myservice","tls":"tls"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            if let Some(V2RayTransport::Grpc(grpc)) = vmess.transport {
                assert_eq!(grpc.service_name, Some("myservice".to_string()));
            } else {
                panic!("Expected gRPC transport");
            }
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_with_fingerprint() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"fp-node","add":"example.com","port":443,"id":"uuid","tls":"tls","fp":"chrome"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert!(vmess.tls.is_some());
            let tls = vmess.tls.unwrap();
            assert!(tls.utls.is_some());
            assert_eq!(tls.utls.unwrap().fingerprint, Some("chrome".to_string()));
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_no_name() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"","add":"example.com","port":443,"id":"uuid"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            // Should use server:port as tag when ps is empty
            assert_eq!(vmess.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_port_as_string() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"test","add":"example.com","port":"8443","id":"uuid"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert_eq!(vmess.server_port, Some(8443));
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_invalid_uri() {
        let parser = VMessParser;
        assert!(parser.parse("vmess://").is_err());
        assert!(parser.parse("vmess://not-base64!@#$").is_err());
        assert!(parser.parse("ss://wrong-scheme").is_err());
    }

    #[test]
    fn test_vmess_invalid_json() {
        let parser = VMessParser;
        let uri = format!("vmess://{}", STANDARD.encode("not json"));
        assert!(parser.parse(&uri).is_err());
    }

    #[test]
    fn test_scheme() {
        let parser = VMessParser;
        assert_eq!(parser.scheme(), "vmess");
    }

    #[test]
    fn test_can_parse() {
        let parser = VMessParser;
        assert!(parser.can_parse("vmess://abc"));
        assert!(!parser.can_parse("ss://abc"));
        assert!(!parser.can_parse("not-a-uri"));
    }

    #[test]
    fn test_vmess_default_security() {
        let parser = VMessParser;
        let json = r#"{"v":"2","ps":"test","add":"example.com","port":443,"id":"uuid"}"#;
        let uri = encode_vmess_json(json);
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            // Should default to "auto" when not specified
            assert_eq!(vmess.security, Some("auto".to_string()));
        } else {
            panic!("Expected VMess outbound");
        }
    }
}

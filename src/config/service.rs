//! Service configuration types for sing-box.
//!
//! This module contains typed configuration for various service types
//! available since sing-box 1.12.0.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::serde_helpers::is_false;
use crate::config::shared::{DialFields, InboundTlsConfig, ListenFields, OutboundTlsConfig};

// ============================================================================
// Service Enum
// ============================================================================

/// Service configuration enum.
///
/// Services are additional components that can be configured in sing-box
/// since version 1.12.0.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Service {
    /// Claude Code Multiplexer service (since 1.13.0)
    Ccm(Box<CcmService>),
    /// Tailscale DERP server (since 1.12.0)
    Derp(Box<DerpService>),
    /// OpenAI Codex Multiplexer service (since 1.13.0)
    Ocm(Box<OcmService>),
    /// Fake systemd-resolved DBUS service (since 1.12.0)
    Resolved(Box<ResolvedService>),
    /// Shadowsocks Server Management API (since 1.12.0)
    #[serde(rename = "ssm-api")]
    SsmApi(Box<SsmApiService>),
}

// ============================================================================
// CCM Service (Claude Code Multiplexer)
// ============================================================================

/// Claude Code Multiplexer service configuration (since 1.13.0).
///
/// Allows accessing a local Claude Code subscription remotely through custom tokens.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CcmService {
    /// Tag of the service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Path to the Claude Code OAuth credentials file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_path: Option<String>,

    /// Path to the file for storing aggregated API usage statistics
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usages_path: Option<String>,

    /// List of authorized users for token authentication
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<CcmUser>,

    /// Custom HTTP headers to send to the Claude API
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Outbound tag for connecting to the Claude API
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// CCM user configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CcmUser {
    /// Username identifier for tracking purposes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Bearer token for authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl CcmService {
    /// Create a new CCM service with listen address and port.
    pub fn new(listen: impl Into<String>, port: u16) -> Self {
        Self {
            listen: ListenFields {
                listen: Some(listen.into()),
                listen_port: Some(port),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Set the tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Set the credential path.
    pub fn with_credential_path(mut self, path: impl Into<String>) -> Self {
        self.credential_path = Some(path.into());
        self
    }

    /// Set the usages path.
    pub fn with_usages_path(mut self, path: impl Into<String>) -> Self {
        self.usages_path = Some(path.into());
        self
    }

    /// Add a user.
    pub fn add_user(mut self, name: impl Into<String>, token: impl Into<String>) -> Self {
        self.users.push(CcmUser {
            name: Some(name.into()),
            token: Some(token.into()),
        });
        self
    }

    /// Set the detour outbound.
    pub fn with_detour(mut self, detour: impl Into<String>) -> Self {
        self.detour = Some(detour.into());
        self
    }

    /// Set TLS configuration.
    pub fn with_tls(mut self, tls: InboundTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

// ============================================================================
// OCM Service (OpenAI Codex Multiplexer)
// ============================================================================

/// OpenAI Codex Multiplexer service configuration (since 1.13.0).
///
/// Allows accessing a local OpenAI Codex subscription remotely through custom tokens.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OcmService {
    /// Tag of the service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Path to the OpenAI OAuth credentials file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_path: Option<String>,

    /// Path to the file for storing aggregated API usage statistics
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usages_path: Option<String>,

    /// List of authorized users for token authentication
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<OcmUser>,

    /// Custom HTTP headers to send to the OpenAI API
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Outbound tag for connecting to the OpenAI API
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// OCM user configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OcmUser {
    /// Username identifier for tracking purposes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Bearer token for authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl OcmService {
    /// Create a new OCM service with listen address and port.
    pub fn new(listen: impl Into<String>, port: u16) -> Self {
        Self {
            listen: ListenFields {
                listen: Some(listen.into()),
                listen_port: Some(port),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Set the tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Set the credential path.
    pub fn with_credential_path(mut self, path: impl Into<String>) -> Self {
        self.credential_path = Some(path.into());
        self
    }

    /// Set the usages path.
    pub fn with_usages_path(mut self, path: impl Into<String>) -> Self {
        self.usages_path = Some(path.into());
        self
    }

    /// Add a user.
    pub fn add_user(mut self, name: impl Into<String>, token: impl Into<String>) -> Self {
        self.users.push(OcmUser {
            name: Some(name.into()),
            token: Some(token.into()),
        });
        self
    }

    /// Set the detour outbound.
    pub fn with_detour(mut self, detour: impl Into<String>) -> Self {
        self.detour = Some(detour.into());
        self
    }

    /// Set TLS configuration.
    pub fn with_tls(mut self, tls: InboundTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

// ============================================================================
// DERP Service
// ============================================================================

/// Tailscale DERP server service configuration (since 1.12.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DerpService {
    /// Tag of the service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Derper configuration file path (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,

    /// Tailscale endpoint tags to verify clients
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify_client_endpoint: Vec<String>,

    /// URLs to verify clients
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify_client_url: Vec<VerifyClientUrl>,

    /// What to serve at the root path (empty, "blank", or URL)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,

    /// Mesh with other DERP servers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_with: Vec<DerpMeshServer>,

    /// Pre-shared key for DERP mesh
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_psk: Option<String>,

    /// Pre-shared key file for DERP mesh
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_psk_file: Option<String>,

    /// STUN server configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun: Option<DerpStunConfig>,
}

/// DERP client verification URL configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VerifyClientUrl {
    /// URL to verify clients
    pub url: String,

    /// Dial fields for the connection
    #[serde(flatten)]
    pub dial: DialFields,
}

/// DERP mesh server configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DerpMeshServer {
    /// DERP server address (required)
    pub server: String,

    /// DERP server port (required)
    pub server_port: u16,

    /// Custom DERP hostname
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// DERP STUN server configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DerpStunConfig {
    /// Enable STUN server
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,
}

impl DerpService {
    /// Create a new DERP service with config path.
    pub fn new(config_path: impl Into<String>) -> Self {
        Self {
            config_path: Some(config_path.into()),
            ..Default::default()
        }
    }

    /// Set the tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Set listen address and port.
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }

    /// Set TLS configuration.
    pub fn with_tls(mut self, tls: InboundTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Add a verify client endpoint.
    pub fn add_verify_client_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.verify_client_endpoint.push(endpoint.into());
        self
    }

    /// Set the home page.
    pub fn with_home(mut self, home: impl Into<String>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Add a mesh server.
    pub fn add_mesh_server(mut self, server: DerpMeshServer) -> Self {
        self.mesh_with.push(server);
        self
    }

    /// Set mesh PSK.
    pub fn with_mesh_psk(mut self, psk: impl Into<String>) -> Self {
        self.mesh_psk = Some(psk.into());
        self
    }

    /// Enable STUN server.
    pub fn with_stun(mut self, port: u16) -> Self {
        self.stun = Some(DerpStunConfig {
            enabled: true,
            listen: ListenFields {
                listen: Some("::".to_string()),
                listen_port: Some(port),
                ..Default::default()
            },
        });
        self
    }
}

// ============================================================================
// Resolved Service
// ============================================================================

/// Fake systemd-resolved DBUS service configuration (since 1.12.0).
///
/// Receives DNS settings from other programs (e.g. NetworkManager)
/// and provides DNS resolution.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResolvedService {
    /// Tag of the service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,
}

impl ResolvedService {
    /// Create a new resolved service with default settings.
    pub fn new() -> Self {
        Self {
            listen: ListenFields {
                listen: Some("127.0.0.53".to_string()),
                listen_port: Some(53),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Set the tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Set listen address and port.
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }
}

// ============================================================================
// SSM-API Service
// ============================================================================

/// Shadowsocks Server Management API service configuration (since 1.12.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SsmApiService {
    /// Tag of the service
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Mapping from HTTP endpoints to Shadowsocks inbound tags (required)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub servers: HashMap<String, String>,

    /// Path to save/restore traffic and user state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_path: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

impl SsmApiService {
    /// Create a new SSM-API service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Set listen address and port.
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }

    /// Add a server mapping.
    pub fn add_server(
        mut self,
        endpoint: impl Into<String>,
        inbound_tag: impl Into<String>,
    ) -> Self {
        self.servers.insert(endpoint.into(), inbound_tag.into());
        self
    }

    /// Set the cache path.
    pub fn with_cache_path(mut self, path: impl Into<String>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Set TLS configuration.
    pub fn with_tls(mut self, tls: InboundTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccm_service_basic() {
        let service = CcmService::new("127.0.0.1", 8080);
        let json = serde_json::to_string(&Service::Ccm(Box::new(service))).unwrap();
        assert!(json.contains(r#""type":"ccm""#));
        assert!(json.contains(r#""listen":"127.0.0.1""#));
        assert!(json.contains(r#""listen_port":8080"#));
    }

    #[test]
    fn test_ccm_service_with_users() {
        let service = CcmService::new("127.0.0.1", 8080)
            .with_tag("ccm-service")
            .add_user("alice", "sk-alice-token")
            .add_user("bob", "sk-bob-token")
            .with_usages_path("./usages.json");

        let json = serde_json::to_string(&Service::Ccm(Box::new(service))).unwrap();
        assert!(json.contains(r#""tag":"ccm-service""#));
        assert!(json.contains(r#""name":"alice""#));
        assert!(json.contains(r#""token":"sk-alice-token""#));
        assert!(json.contains(r#""usages_path":"./usages.json""#));
    }

    #[test]
    fn test_ocm_service_basic() {
        let service = OcmService::new("127.0.0.1", 8080).with_credential_path("~/.codex/auth.json");

        let json = serde_json::to_string(&Service::Ocm(Box::new(service))).unwrap();
        assert!(json.contains(r#""type":"ocm""#));
        assert!(json.contains(r#""credential_path":"~/.codex/auth.json""#));
    }

    #[test]
    fn test_derp_service_basic() {
        let service = DerpService::new("derper.key")
            .listen("0.0.0.0", 443)
            .with_stun(3478);

        let json = serde_json::to_string(&Service::Derp(Box::new(service))).unwrap();
        assert!(json.contains(r#""type":"derp""#));
        assert!(json.contains(r#""config_path":"derper.key""#));
        assert!(json.contains(r#""enabled":true"#));
    }

    #[test]
    fn test_derp_service_with_mesh() {
        let mesh_server = DerpMeshServer {
            server: "derp1.example.com".to_string(),
            server_port: 443,
            host: Some("derp1".to_string()),
            ..Default::default()
        };

        let service = DerpService::new("derper.key")
            .add_mesh_server(mesh_server)
            .with_mesh_psk("secret-psk");

        let json = serde_json::to_string(&Service::Derp(Box::new(service))).unwrap();
        assert!(json.contains(r#""server":"derp1.example.com""#));
        assert!(json.contains(r#""mesh_psk":"secret-psk""#));
    }

    #[test]
    fn test_resolved_service() {
        let service = ResolvedService::new().with_tag("resolved");

        let json = serde_json::to_string(&Service::Resolved(Box::new(service))).unwrap();
        assert!(json.contains(r#""type":"resolved""#));
        assert!(json.contains(r#""listen":"127.0.0.53""#));
        assert!(json.contains(r#""listen_port":53"#));
    }

    #[test]
    fn test_ssm_api_service() {
        let service = SsmApiService::new()
            .with_tag("ssm")
            .listen("127.0.0.1", 8080)
            .add_server("/", "ss-in")
            .with_cache_path("./state.json");

        let json = serde_json::to_string(&Service::SsmApi(Box::new(service))).unwrap();
        assert!(json.contains(r#""type":"ssm-api""#));
        assert!(json.contains(r#""tag":"ssm""#));
        assert!(json.contains(r#""/":"ss-in""#) || json.contains(r#""ss-in""#));
        assert!(json.contains(r#""cache_path":"./state.json""#));
    }

    #[test]
    fn test_service_roundtrip() {
        let original = Service::Ccm(Box::new(
            CcmService::new("127.0.0.1", 8080)
                .with_tag("ccm")
                .add_user("user1", "token1"),
        ));

        let json = serde_json::to_string_pretty(&original).unwrap();
        let parsed: Service = serde_json::from_str(&json).unwrap();

        match parsed {
            Service::Ccm(ccm) => {
                assert_eq!(ccm.tag, Some("ccm".to_string()));
                assert_eq!(ccm.users.len(), 1);
                assert_eq!(ccm.users[0].name, Some("user1".to_string()));
            }
            _ => panic!("Expected Ccm service"),
        }
    }

    #[test]
    fn test_derp_stun_config() {
        let stun = DerpStunConfig {
            enabled: true,
            listen: ListenFields {
                listen: Some("::".to_string()),
                listen_port: Some(3478),
                ..Default::default()
            },
        };

        let json = serde_json::to_string(&stun).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""listen":"::""#));
        assert!(json.contains(r#""listen_port":3478"#));
    }

    #[test]
    fn test_verify_client_url() {
        let url = VerifyClientUrl {
            url: "https://headscale.example.com/verify".to_string(),
            dial: DialFields::default(),
        };

        let json = serde_json::to_string(&url).unwrap();
        assert!(json.contains(r#""url":"https://headscale.example.com/verify""#));
    }

    #[test]
    fn test_deserialization_from_json() {
        let json = r#"{
            "type": "ccm",
            "listen": "0.0.0.0",
            "listen_port": 8080,
            "users": [
                {"name": "alice", "token": "token-a"},
                {"name": "bob", "token": "token-b"}
            ]
        }"#;

        let service: Service = serde_json::from_str(json).unwrap();
        match service {
            Service::Ccm(ccm) => {
                assert_eq!(ccm.listen.listen, Some("0.0.0.0".to_string()));
                assert_eq!(ccm.listen.listen_port, Some(8080));
                assert_eq!(ccm.users.len(), 2);
            }
            _ => panic!("Expected Ccm service"),
        }
    }

    #[test]
    fn test_ssm_api_deserialization() {
        let json = r#"{
            "type": "ssm-api",
            "listen": "127.0.0.1",
            "listen_port": 8080,
            "servers": {
                "/": "ss-in",
                "/v2": "ss-in-v2"
            }
        }"#;

        let service: Service = serde_json::from_str(json).unwrap();
        match service {
            Service::SsmApi(ssm) => {
                assert_eq!(ssm.servers.len(), 2);
                assert_eq!(ssm.servers.get("/"), Some(&"ss-in".to_string()));
            }
            _ => panic!("Expected SsmApi service"),
        }
    }

    #[test]
    fn test_derp_mesh_server() {
        let mesh = DerpMeshServer {
            server: "derp.example.com".to_string(),
            server_port: 443,
            host: Some("custom-host".to_string()),
            tls: None,
            dial: DialFields::default(),
        };

        let json = serde_json::to_string(&mesh).unwrap();
        assert!(json.contains(r#""server":"derp.example.com""#));
        assert!(json.contains(r#""server_port":443"#));
        assert!(json.contains(r#""host":"custom-host""#));
    }
}

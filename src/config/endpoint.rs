use serde::{Deserialize, Serialize};

use crate::config::shared::DialFields;
use crate::config::util::{
    default_wireguard_mtu, is_default_wireguard_mtu, is_false, is_zero_u16, is_zero_u32,
};

/// Endpoint configuration enum (since sing-box 1.11.0)
///
/// An endpoint is a protocol with inbound and outbound behavior.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Endpoint {
    /// WireGuard endpoint
    WireGuard(WireGuardEndpoint),
    /// Tailscale endpoint (since sing-box 1.12.0)
    Tailscale(TailscaleEndpoint),
}

/// WireGuard endpoint configuration (since sing-box 1.11.0)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireGuardEndpoint {
    /// The tag of the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Use system interface
    /// Requires privilege and cannot conflict with existing system interfaces
    #[serde(default, skip_serializing_if = "is_false")]
    pub system: bool,

    /// Custom interface name for system interface
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// WireGuard MTU (default: 1408)
    #[serde(
        default = "default_wireguard_mtu",
        skip_serializing_if = "is_default_wireguard_mtu"
    )]
    pub mtu: u32,

    /// List of IP (v4 or v6) address prefixes to be assigned to the interface (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<String>,

    /// WireGuard private key (required, base64-encoded)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// WireGuard listen port
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub listen_port: u16,

    /// List of WireGuard peers (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WireGuardPeer>,

    /// UDP NAT expiration time (default: "5m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// WireGuard worker count (default: CPU count)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub workers: u32,

    /// Dial fields for outbound connections
    #[serde(flatten)]
    pub dial: DialFields,
}

impl Default for WireGuardEndpoint {
    fn default() -> Self {
        Self {
            tag: None,
            system: false,
            name: None,
            mtu: 1408,
            address: Vec::new(),
            private_key: None,
            listen_port: 0,
            peers: Vec::new(),
            udp_timeout: None,
            workers: 0,
            dial: DialFields::default(),
        }
    }
}

/// WireGuard peer configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WireGuardPeer {
    /// WireGuard peer address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// WireGuard peer port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// WireGuard peer public key (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// WireGuard peer pre-shared key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,

    /// WireGuard allowed IPs (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,

    /// WireGuard persistent keepalive interval, in seconds
    /// Disabled by default
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub persistent_keepalive_interval: u32,

    /// WireGuard reserved field bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
}

/// Tailscale endpoint configuration (since sing-box 1.12.0)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TailscaleEndpoint {
    /// The tag of the endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// The directory where the Tailscale state is stored
    /// Default: "tailscale"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_directory: Option<String>,

    /// The auth key to create the node
    /// Not required - sing-box will log the login URL by default
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,

    /// The coordination server URL
    /// Default: "https://controlplane.tailscale.com"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,

    /// Register as an Ephemeral node
    #[serde(default, skip_serializing_if = "is_false")]
    pub ephemeral: bool,

    /// The hostname of the node
    /// Default: system hostname
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Accept routes advertised by other nodes
    #[serde(default, skip_serializing_if = "is_false")]
    pub accept_routes: bool,

    /// The exit node name or IP address to use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,

    /// Route locally accessible subnets directly or via exit node
    #[serde(default, skip_serializing_if = "is_false")]
    pub exit_node_allow_lan_access: bool,

    /// CIDR prefixes to advertise into the Tailscale network
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<String>,

    /// Advertise this node as an exit node
    #[serde(default, skip_serializing_if = "is_false")]
    pub advertise_exit_node: bool,

    /// Port for incoming relay connections (since sing-box 1.13.0)
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub relay_server_port: u16,

    /// Static endpoints for the relay server (since sing-box 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_server_static_endpoints: Vec<String>,

    /// Create a system TUN interface for Tailscale (since sing-box 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub system_interface: bool,

    /// Custom TUN interface name (since sing-box 1.13.0)
    /// Default: "tailscale" (or "utun" on macOS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_interface_name: Option<String>,

    /// Override the TUN MTU (since sing-box 1.13.0)
    /// Default: Tailscale's own MTU
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_interface_mtu: u32,

    /// UDP NAT expiration time (default: "5m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// Dial fields for control plane connections
    /// Note: Dial fields only control how it connects to the control plane
    #[serde(flatten)]
    pub dial: DialFields,
}

impl WireGuardEndpoint {
    /// Create a new WireGuard endpoint with required fields
    pub fn new(
        tag: impl Into<String>,
        private_key: impl Into<String>,
        address: Vec<String>,
    ) -> Self {
        Self {
            tag: Some(tag.into()),
            private_key: Some(private_key.into()),
            address,
            mtu: 1408,
            ..Default::default()
        }
    }

    /// Add a peer to the WireGuard endpoint
    pub fn add_peer(mut self, peer: WireGuardPeer) -> Self {
        self.peers.push(peer);
        self
    }
}

impl WireGuardPeer {
    /// Create a new WireGuard peer with required fields
    pub fn new(public_key: impl Into<String>, allowed_ips: Vec<String>) -> Self {
        Self {
            public_key: Some(public_key.into()),
            allowed_ips,
            ..Default::default()
        }
    }

    /// Set peer address and port
    pub fn with_address(mut self, address: impl Into<String>, port: u16) -> Self {
        self.address = Some(address.into());
        self.port = Some(port);
        self
    }

    /// Set pre-shared key
    pub fn with_psk(mut self, psk: impl Into<String>) -> Self {
        self.pre_shared_key = Some(psk.into());
        self
    }

    /// Set persistent keepalive interval
    pub fn with_keepalive(mut self, interval: u32) -> Self {
        self.persistent_keepalive_interval = interval;
        self
    }
}

impl TailscaleEndpoint {
    /// Create a new Tailscale endpoint with a tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set the auth key for automatic node creation
    pub fn with_auth_key(mut self, auth_key: impl Into<String>) -> Self {
        self.auth_key = Some(auth_key.into());
        self
    }

    /// Set the control URL for self-hosted Headscale
    pub fn with_control_url(mut self, url: impl Into<String>) -> Self {
        self.control_url = Some(url.into());
        self
    }

    /// Set the hostname
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    /// Configure as an exit node
    pub fn as_exit_node(mut self) -> Self {
        self.advertise_exit_node = true;
        self
    }

    /// Use a specific exit node
    pub fn use_exit_node(mut self, exit_node: impl Into<String>) -> Self {
        self.exit_node = Some(exit_node.into());
        self
    }

    /// Advertise routes
    pub fn advertise_routes(mut self, routes: Vec<String>) -> Self {
        self.advertise_routes = routes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_endpoint_serialization() {
        let endpoint = WireGuardEndpoint {
            tag: Some("wg-ep".to_string()),
            private_key: Some("ABC123==".to_string()),
            address: vec!["10.0.0.1/24".to_string()],
            peers: vec![WireGuardPeer {
                address: Some("127.0.0.1".to_string()),
                port: Some(51820),
                public_key: Some("XYZ789==".to_string()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""tag":"wg-ep""#));
        assert!(json.contains(r#""private_key":"ABC123==""#));
        assert!(json.contains(r#""address":["10.0.0.1/24"]"#));
        assert!(json.contains(r#""public_key":"XYZ789==""#));
    }

    #[test]
    fn test_wireguard_endpoint_default_mtu() {
        let endpoint = WireGuardEndpoint::default();
        assert_eq!(endpoint.mtu, 1408);

        // Default MTU should not be serialized
        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(!json.contains("mtu"));
    }

    #[test]
    fn test_wireguard_endpoint_custom_mtu() {
        let endpoint = WireGuardEndpoint {
            mtu: 1500,
            ..Default::default()
        };
        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""mtu":1500"#));
    }

    #[test]
    fn test_wireguard_peer_with_reserved() {
        let peer = WireGuardPeer {
            public_key: Some("XYZ==".to_string()),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            reserved: Some([1, 2, 3]),
            ..Default::default()
        };
        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains(r#""reserved":[1,2,3]"#));
    }

    #[test]
    fn test_wireguard_peer_builder() {
        let peer = WireGuardPeer::new("public_key==", vec!["0.0.0.0/0".to_string()])
            .with_address("1.2.3.4", 51820)
            .with_psk("psk==")
            .with_keepalive(25);

        assert_eq!(peer.public_key, Some("public_key==".to_string()));
        assert_eq!(peer.address, Some("1.2.3.4".to_string()));
        assert_eq!(peer.port, Some(51820));
        assert_eq!(peer.pre_shared_key, Some("psk==".to_string()));
        assert_eq!(peer.persistent_keepalive_interval, 25);
    }

    #[test]
    fn test_tailscale_endpoint_serialization() {
        let endpoint = TailscaleEndpoint {
            tag: Some("ts-ep".to_string()),
            hostname: Some("my-node".to_string()),
            accept_routes: true,
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""tag":"ts-ep""#));
        assert!(json.contains(r#""hostname":"my-node""#));
        assert!(json.contains(r#""accept_routes":true"#));
    }

    #[test]
    fn test_tailscale_endpoint_with_exit_node() {
        let endpoint = TailscaleEndpoint {
            tag: Some("ts-exit".to_string()),
            advertise_exit_node: true,
            advertise_routes: vec!["192.168.1.0/24".to_string()],
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""advertise_exit_node":true"#));
        assert!(json.contains(r#""advertise_routes":["192.168.1.0/24"]"#));
    }

    #[test]
    fn test_tailscale_endpoint_v113_fields() {
        let endpoint = TailscaleEndpoint {
            tag: Some("ts-ep".to_string()),
            relay_server_port: 41641,
            relay_server_static_endpoints: vec!["1.2.3.4:41641".to_string()],
            system_interface: true,
            system_interface_name: Some("utun100".to_string()),
            system_interface_mtu: 1500,
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""relay_server_port":41641"#));
        assert!(json.contains(r#""relay_server_static_endpoints":["1.2.3.4:41641"]"#));
        assert!(json.contains(r#""system_interface":true"#));
        assert!(json.contains(r#""system_interface_name":"utun100""#));
        assert!(json.contains(r#""system_interface_mtu":1500"#));
    }

    #[test]
    fn test_tailscale_endpoint_builder() {
        let endpoint = TailscaleEndpoint::new("ts-test")
            .with_auth_key("tskey-auth-xxx")
            .with_hostname("my-host")
            .with_control_url("https://headscale.example.com")
            .advertise_routes(vec!["10.0.0.0/8".to_string()]);

        assert_eq!(endpoint.tag, Some("ts-test".to_string()));
        assert_eq!(endpoint.auth_key, Some("tskey-auth-xxx".to_string()));
        assert_eq!(endpoint.hostname, Some("my-host".to_string()));
        assert_eq!(
            endpoint.control_url,
            Some("https://headscale.example.com".to_string())
        );
        assert_eq!(endpoint.advertise_routes, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn test_endpoint_enum_wireguard() {
        let wg = WireGuardEndpoint {
            tag: Some("wg-ep".to_string()),
            private_key: Some("key==".to_string()),
            address: vec!["10.0.0.1/24".to_string()],
            ..Default::default()
        };
        let endpoint = Endpoint::WireGuard(wg);

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""type":"wireguard""#));
        assert!(json.contains(r#""tag":"wg-ep""#));
    }

    #[test]
    fn test_endpoint_enum_tailscale() {
        let ts = TailscaleEndpoint {
            tag: Some("ts-ep".to_string()),
            hostname: Some("node1".to_string()),
            ..Default::default()
        };
        let endpoint = Endpoint::Tailscale(ts);

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""type":"tailscale""#));
        assert!(json.contains(r#""tag":"ts-ep""#));
    }

    #[test]
    fn test_endpoint_deserialization_wireguard() {
        let json = r#"{
            "type": "wireguard",
            "tag": "wg-test",
            "private_key": "abc==",
            "address": ["10.0.0.1/24"],
            "peers": [{
                "public_key": "xyz==",
                "allowed_ips": ["0.0.0.0/0"],
                "address": "1.2.3.4",
                "port": 51820
            }]
        }"#;

        let endpoint: Endpoint = serde_json::from_str(json).unwrap();
        match endpoint {
            Endpoint::WireGuard(wg) => {
                assert_eq!(wg.tag, Some("wg-test".to_string()));
                assert_eq!(wg.private_key, Some("abc==".to_string()));
                assert_eq!(wg.peers.len(), 1);
                assert_eq!(wg.peers[0].port, Some(51820));
            }
            _ => panic!("Expected WireGuard endpoint"),
        }
    }

    #[test]
    fn test_endpoint_deserialization_tailscale() {
        let json = r#"{
            "type": "tailscale",
            "tag": "ts-test",
            "hostname": "my-node",
            "accept_routes": true,
            "advertise_routes": ["192.168.0.0/24"]
        }"#;

        let endpoint: Endpoint = serde_json::from_str(json).unwrap();
        match endpoint {
            Endpoint::Tailscale(ts) => {
                assert_eq!(ts.tag, Some("ts-test".to_string()));
                assert_eq!(ts.hostname, Some("my-node".to_string()));
                assert!(ts.accept_routes);
                assert_eq!(ts.advertise_routes, vec!["192.168.0.0/24".to_string()]);
            }
            _ => panic!("Expected Tailscale endpoint"),
        }
    }

    #[test]
    fn test_wireguard_endpoint_with_dial_fields() {
        let endpoint = WireGuardEndpoint {
            tag: Some("wg-dial".to_string()),
            private_key: Some("key==".to_string()),
            address: vec!["10.0.0.1/24".to_string()],
            dial: DialFields {
                detour: Some("proxy".to_string()),
                tcp_fast_open: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""detour":"proxy""#));
        assert!(json.contains(r#""tcp_fast_open":true"#));
    }

    #[test]
    fn test_tailscale_endpoint_with_dial_fields() {
        let endpoint = TailscaleEndpoint {
            tag: Some("ts-dial".to_string()),
            dial: DialFields {
                connect_timeout: Some("30s".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let json = serde_json::to_string(&endpoint).unwrap();
        assert!(json.contains(r#""connect_timeout":"30s""#));
    }

    #[test]
    fn test_wireguard_endpoint_builder() {
        let peer = WireGuardPeer::new("pub_key==", vec!["0.0.0.0/0".to_string()])
            .with_address("1.2.3.4", 51820)
            .with_keepalive(25);

        let endpoint =
            WireGuardEndpoint::new("wg-built", "priv_key==", vec!["10.0.0.1/24".to_string()])
                .add_peer(peer);

        assert_eq!(endpoint.tag, Some("wg-built".to_string()));
        assert_eq!(endpoint.private_key, Some("priv_key==".to_string()));
        assert_eq!(endpoint.peers.len(), 1);
        assert_eq!(endpoint.peers[0].persistent_keepalive_interval, 25);
    }

    #[test]
    fn test_empty_wireguard_serializes_minimal() {
        let endpoint = WireGuardEndpoint::default();
        let json = serde_json::to_string(&endpoint).unwrap();
        // Should only have empty object or minimal fields
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_empty_tailscale_serializes_minimal() {
        let endpoint = TailscaleEndpoint::default();
        let json = serde_json::to_string(&endpoint).unwrap();
        // Should only have empty object or minimal fields
        assert_eq!(json, "{}");
    }
}

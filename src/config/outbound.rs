use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::shared::{DialFields, OutboundTlsConfig};
use crate::config::util::{default_wireguard_mtu, is_default_wireguard_mtu, is_false, is_zero_u32};

// ============================================================================
// Outbound Enum
// ============================================================================

/// Outbound configuration enum
///
/// Represents all available outbound types in sing-box.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Outbound {
    /// Direct outbound (send requests directly)
    Direct(DirectOutbound),
    /// Block outbound (block requests)
    Block(BlockOutbound),
    /// SOCKS outbound (SOCKS4/4a/5 client)
    #[serde(rename = "socks")]
    Socks(SocksOutbound),
    /// HTTP outbound (HTTP CONNECT proxy client)
    #[serde(rename = "http")]
    Http(HttpOutbound),
    /// Shadowsocks outbound
    Shadowsocks(ShadowsocksOutbound),
    /// VMess outbound
    #[serde(rename = "vmess")]
    VMess(VMessOutbound),
    /// Trojan outbound
    Trojan(TrojanOutbound),
    /// WireGuard outbound
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardOutbound),
    /// Hysteria outbound
    Hysteria(HysteriaOutbound),
    /// VLESS outbound
    #[serde(rename = "vless")]
    VLess(VLessOutbound),
    /// ShadowTLS outbound
    #[serde(rename = "shadowtls")]
    ShadowTls(ShadowTlsOutbound),
    /// TUIC outbound
    #[serde(rename = "tuic")]
    Tuic(TuicOutbound),
    /// Hysteria2 outbound
    Hysteria2(Hysteria2Outbound),
    /// AnyTLS outbound
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsOutbound),
    /// Tor outbound
    Tor(TorOutbound),
    /// SSH outbound
    #[serde(rename = "ssh")]
    Ssh(SshOutbound),
    /// DNS outbound
    #[serde(rename = "dns")]
    Dns(DnsOutbound),
    /// Selector outbound (manual selection)
    Selector(SelectorOutbound),
    /// URLTest outbound (automatic selection)
    #[serde(rename = "urltest")]
    UrlTest(UrlTestOutbound),
    /// NaiveProxy outbound
    Naive(NaiveOutbound),
}

// ============================================================================
// Common Types
// ============================================================================

/// Multiplex configuration for outbound
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboundMultiplex {
    /// Enable multiplex
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Multiplex protocol: smux, yamux, h2mux (default: h2mux)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Maximum connections (conflicts with max_streams)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,

    /// Minimum streams before opening new connection (conflicts with max_streams)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_streams: Option<u32>,

    /// Maximum streams per connection (conflicts with max_connections and min_streams)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_streams: Option<u32>,

    /// Enable padding
    #[serde(default, skip_serializing_if = "is_false")]
    pub padding: bool,

    /// TCP Brutal configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brutal: Option<OutboundTcpBrutal>,
}

/// TCP Brutal configuration for outbound
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboundTcpBrutal {
    /// Enable TCP Brutal
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Upload bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
}

/// UDP over TCP configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum UdpOverTcp {
    /// Simple enable/disable
    Enabled(bool),
    /// Full configuration
    Config(UdpOverTcpConfig),
}

/// UDP over TCP full configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UdpOverTcpConfig {
    /// Enable UDP over TCP
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Protocol version: 1 or 2 (default: 2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
}

/// V2Ray transport configuration for outbound
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum V2RayTransport {
    /// HTTP transport
    Http(HttpTransport),
    /// WebSocket transport
    #[serde(rename = "ws")]
    WebSocket(WebSocketTransport),
    /// QUIC transport
    Quic(QuicTransport),
    /// gRPC transport
    #[serde(rename = "grpc")]
    Grpc(GrpcTransport),
    /// HTTPUpgrade transport
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(HttpUpgradeTransport),
}

/// HTTP transport configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpTransport {
    /// Host domains
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,

    /// HTTP request path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// HTTP request method
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Extra headers
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Idle timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,

    /// Ping timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_timeout: Option<String>,
}

/// WebSocket transport configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WebSocketTransport {
    /// HTTP request path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Extra headers
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Max early data size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_early_data: u32,

    /// Early data header name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
}

/// QUIC transport configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct QuicTransport {}

/// gRPC transport configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GrpcTransport {
    /// gRPC service name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    /// Idle timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,

    /// Ping timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_timeout: Option<String>,

    /// Permit without stream
    #[serde(default, skip_serializing_if = "is_false")]
    pub permit_without_stream: bool,
}

/// HTTPUpgrade transport configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpUpgradeTransport {
    /// Host domain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// HTTP request path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Extra headers
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
}

// ============================================================================
// Outbound Types
// ============================================================================

/// Direct outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DirectOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Deprecated: Override destination address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    /// Deprecated: Override destination port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Block outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BlockOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// SOCKS outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SocksOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// SOCKS version: 4, 4a, or 5 (default: 5)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// SOCKS username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// SOCKS5 password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// UDP over TCP configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<UdpOverTcp>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// HTTP outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Basic auth username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Basic auth password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// HTTP request path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Extra headers
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Shadowsocks outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowsocksOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Encryption method (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Password (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// SIP003 plugin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,

    /// SIP003 plugin options
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// UDP over TCP configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<UdpOverTcp>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<OutboundMultiplex>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// VMess outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VMessOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// VMess user UUID (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Security: auto, none, zero, aes-128-gcm, chacha20-poly1305
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,

    /// Alter ID (0 = AEAD, 1 = legacy)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub alter_id: u32,

    /// Enable global padding
    #[serde(default, skip_serializing_if = "is_false")]
    pub global_padding: bool,

    /// Enable authenticated length
    #[serde(default, skip_serializing_if = "is_false")]
    pub authenticated_length: bool,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// UDP packet encoding: packetaddr, xudp
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<OutboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Trojan outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrojanOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Trojan password (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<OutboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// WireGuard outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireGuardOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Use system interface
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

    /// GSO support (Linux only)
    #[serde(default, skip_serializing_if = "is_false")]
    pub gso: bool,

    /// Local addresses (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_address: Vec<String>,

    /// Private key (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// Peers (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WireGuardPeer>,

    /// Server address (single peer shorthand)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (single peer shorthand)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Peer public key (single peer shorthand)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_public_key: Option<String>,

    /// Pre-shared key (single peer shorthand)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,

    /// Reserved bytes (single peer shorthand)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,

    /// Worker count (default: CPU count)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub workers: u32,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

impl Default for WireGuardOutbound {
    fn default() -> Self {
        Self {
            tag: None,
            system: false,
            name: None,
            mtu: 1408,
            gso: false,
            local_address: Vec::new(),
            private_key: None,
            peers: Vec::new(),
            server: None,
            server_port: None,
            peer_public_key: None,
            pre_shared_key: None,
            reserved: None,
            workers: 0,
            network: None,
            dial: DialFields::default(),
        }
    }
}

/// WireGuard peer configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WireGuardPeer {
    /// Peer server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Peer server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Peer public key (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Pre-shared key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,

    /// Allowed IPs (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,

    /// Reserved bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<[u8; 3]>,
}

/// Hysteria outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HysteriaOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Upload bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,

    /// Obfuscation password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,

    /// Authentication string
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_str: Option<String>,

    /// Receive window connection size
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_window_conn: Option<u64>,

    /// Receive window size
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_window: Option<u64>,

    /// Disable MTU discovery
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_mtu_discovery: bool,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// VLESS outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VLessOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// VLESS UUID (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// VLESS flow (e.g., "xtls-rprx-vision")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// UDP packet encoding: packetaddr, xudp (default: xudp)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<OutboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// ShadowTLS outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowTlsOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// ShadowTLS protocol version: 1, 2, or 3 (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// ShadowTLS password (for v2/v3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// TUIC outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TuicOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// TUIC UUID (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// TUIC password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Congestion control: cubic, new_reno, bbr (default: cubic)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,

    /// UDP relay mode: native, quic (default: native)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,

    /// UDP over stream
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_over_stream: bool,

    /// Zero RTT handshake
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_rtt_handshake: bool,

    /// Heartbeat interval
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Hysteria2 outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Hysteria2Outbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Server port range list (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_ports: Vec<String>,

    /// Port hopping interval (since 1.11.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<String>,

    /// Upload bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,

    /// Obfuscation configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,

    /// Authentication password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Enabled network: tcp, udp, or both (default: both)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Enable Brutal debug logging
    #[serde(default, skip_serializing_if = "is_false")]
    pub brutal_debug: bool,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Hysteria2 obfuscation configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Hysteria2Obfs {
    /// Obfuscation type (only "salamander")
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub obfs_type: Option<String>,

    /// Obfuscation password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// AnyTLS outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AnyTlsOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Tor outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TorOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Tor executable path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,

    /// Extra arguments for Tor
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,

    /// Data directory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_directory: Option<String>,

    /// Tor configuration options
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub options: HashMap<String, String>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// SSH outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SshOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// SSH username (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// SSH password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Private key content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// Private key path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,

    /// Private key passphrase
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_passphrase: Option<String>,

    /// Host key algorithms
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_key_algorithms: Vec<String>,

    /// Host key content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,

    /// Host key path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_path: Option<String>,

    /// Client version string
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

/// DNS outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DnsOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Selector outbound configuration (manual selection)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SelectorOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// List of outbound tags to select from (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,

    /// Default outbound tag
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// Interrupt existing connections when selection changes
    #[serde(default, skip_serializing_if = "is_false")]
    pub interrupt_exist_connections: bool,
}

/// URLTest outbound configuration (automatic selection)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UrlTestOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// List of outbound tags to test (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,

    /// Test URL (default: https://www.gstatic.com/generate_204)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Test interval (default: 3m)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Tolerance in milliseconds (default: 50)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tolerance: u32,

    /// Idle timeout (default: 30m)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<String>,

    /// Interrupt existing connections when selection changes
    #[serde(default, skip_serializing_if = "is_false")]
    pub interrupt_exist_connections: bool,
}

/// NaiveProxy outbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NaiveOutbound {
    /// Tag of the outbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Server address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Enabled network: tcp or udp (default: tcp)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<OutboundTlsConfig>,

    /// Dial fields
    #[serde(flatten)]
    pub dial: DialFields,
}

// ============================================================================
// Builder Implementations
// ============================================================================

impl DirectOutbound {
    /// Create a new direct outbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }
}

impl BlockOutbound {
    /// Create a new block outbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
        }
    }
}

impl SocksOutbound {
    /// Create a new SOCKS outbound with required fields
    pub fn new(tag: impl Into<String>, server: impl Into<String>, server_port: u16) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            ..Default::default()
        }
    }

    /// Set authentication
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
}

impl HttpOutbound {
    /// Create a new HTTP outbound with required fields
    pub fn new(tag: impl Into<String>, server: impl Into<String>, server_port: u16) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            ..Default::default()
        }
    }

    /// Set authentication
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }
}

impl ShadowsocksOutbound {
    /// Create a new Shadowsocks outbound with required fields
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        method: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            method: Some(method.into()),
            password: Some(password.into()),
            ..Default::default()
        }
    }
}

impl VMessOutbound {
    /// Create a new VMess outbound with required fields
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        uuid: impl Into<String>,
    ) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            uuid: Some(uuid.into()),
            ..Default::default()
        }
    }

    /// Set security method
    pub fn with_security(mut self, security: impl Into<String>) -> Self {
        self.security = Some(security.into());
        self
    }
}

impl TrojanOutbound {
    /// Create a new Trojan outbound with required fields
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            password: Some(password.into()),
            ..Default::default()
        }
    }
}

impl VLessOutbound {
    /// Create a new VLESS outbound with required fields
    pub fn new(
        tag: impl Into<String>,
        server: impl Into<String>,
        server_port: u16,
        uuid: impl Into<String>,
    ) -> Self {
        Self {
            tag: Some(tag.into()),
            server: Some(server.into()),
            server_port: Some(server_port),
            uuid: Some(uuid.into()),
            ..Default::default()
        }
    }

    /// Set VLESS flow
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = Some(flow.into());
        self
    }
}

impl SelectorOutbound {
    /// Create a new selector outbound with tag
    pub fn new(tag: impl Into<String>, outbounds: Vec<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            outbounds,
            ..Default::default()
        }
    }

    /// Set default outbound
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
}

impl UrlTestOutbound {
    /// Create a new urltest outbound with tag
    pub fn new(tag: impl Into<String>, outbounds: Vec<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            outbounds,
            ..Default::default()
        }
    }

    /// Set test URL
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set test interval
    pub fn with_interval(mut self, interval: impl Into<String>) -> Self {
        self.interval = Some(interval.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_outbound_serialization() {
        let outbound = DirectOutbound::new("direct");
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""tag":"direct""#));
    }

    #[test]
    fn test_outbound_enum_direct() {
        let direct = DirectOutbound::new("direct");
        let outbound = Outbound::Direct(direct);

        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"direct""#));
        assert!(json.contains(r#""tag":"direct""#));
    }

    #[test]
    fn test_outbound_enum_block() {
        let block = BlockOutbound::new("block");
        let outbound = Outbound::Block(block);

        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"block""#));
    }

    #[test]
    fn test_socks_outbound_serialization() {
        let socks = SocksOutbound::new("socks-out", "127.0.0.1", 1080).with_auth("user", "pass");

        let outbound = Outbound::Socks(socks);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"socks""#));
        assert!(json.contains(r#""server":"127.0.0.1""#));
        assert!(json.contains(r#""server_port":1080"#));
        assert!(json.contains(r#""username":"user""#));
    }

    #[test]
    fn test_http_outbound_serialization() {
        let http = HttpOutbound::new("http-out", "proxy.example.com", 8080);

        let outbound = Outbound::Http(http);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"http""#));
        assert!(json.contains(r#""server":"proxy.example.com""#));
    }

    #[test]
    fn test_shadowsocks_outbound_serialization() {
        let ss = ShadowsocksOutbound::new(
            "ss-out",
            "ss.example.com",
            8388,
            "2022-blake3-aes-128-gcm",
            "password123",
        );

        let outbound = Outbound::Shadowsocks(ss);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"shadowsocks""#));
        assert!(json.contains(r#""method":"2022-blake3-aes-128-gcm""#));
    }

    #[test]
    fn test_vmess_outbound_serialization() {
        let vmess = VMessOutbound::new(
            "vmess-out",
            "vmess.example.com",
            443,
            "bf000d23-0752-40b4-affe-68f7707a9661",
        )
        .with_security("auto");

        let outbound = Outbound::VMess(vmess);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"vmess""#));
        assert!(json.contains(r#""uuid":"bf000d23-0752-40b4-affe-68f7707a9661""#));
        assert!(json.contains(r#""security":"auto""#));
    }

    #[test]
    fn test_trojan_outbound_serialization() {
        let trojan = TrojanOutbound::new("trojan-out", "trojan.example.com", 443, "password123");

        let outbound = Outbound::Trojan(trojan);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"trojan""#));
        assert!(json.contains(r#""password":"password123""#));
    }

    #[test]
    fn test_vless_outbound_serialization() {
        let vless = VLessOutbound::new(
            "vless-out",
            "vless.example.com",
            443,
            "bf000d23-0752-40b4-affe-68f7707a9661",
        )
        .with_flow("xtls-rprx-vision");

        let outbound = Outbound::VLess(vless);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"vless""#));
        assert!(json.contains(r#""flow":"xtls-rprx-vision""#));
    }

    #[test]
    fn test_selector_outbound_serialization() {
        let selector =
            SelectorOutbound::new("select", vec!["proxy-a".to_string(), "proxy-b".to_string()])
                .with_default("proxy-a");

        let outbound = Outbound::Selector(selector);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"selector""#));
        assert!(json.contains(r#""outbounds":["proxy-a","proxy-b"]"#));
        assert!(json.contains(r#""default":"proxy-a""#));
    }

    #[test]
    fn test_urltest_outbound_serialization() {
        let urltest =
            UrlTestOutbound::new("auto", vec!["proxy-a".to_string(), "proxy-b".to_string()])
                .with_url("https://www.google.com/generate_204")
                .with_interval("5m");

        let outbound = Outbound::UrlTest(urltest);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"urltest""#));
        assert!(json.contains(r#""url":"https://www.google.com/generate_204""#));
        assert!(json.contains(r#""interval":"5m""#));
    }

    #[test]
    fn test_wireguard_outbound_serialization() {
        let wg = WireGuardOutbound {
            tag: Some("wg-out".to_string()),
            local_address: vec!["10.0.0.2/32".to_string()],
            private_key: Some("private_key_here".to_string()),
            peers: vec![WireGuardPeer {
                server: Some("wg.example.com".to_string()),
                server_port: Some(51820),
                public_key: Some("public_key_here".to_string()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let outbound = Outbound::WireGuard(wg);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"wireguard""#));
        assert!(json.contains(r#""private_key":"private_key_here""#));
    }

    #[test]
    fn test_hysteria2_outbound_serialization() {
        let hy2 = Hysteria2Outbound {
            tag: Some("hy2-out".to_string()),
            server: Some("hy2.example.com".to_string()),
            server_port: Some(443),
            up_mbps: Some(100),
            down_mbps: Some(100),
            password: Some("password123".to_string()),
            obfs: Some(Hysteria2Obfs {
                obfs_type: Some("salamander".to_string()),
                password: Some("obfs_password".to_string()),
            }),
            ..Default::default()
        };

        let outbound = Outbound::Hysteria2(hy2);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"hysteria2""#));
        assert!(json.contains(r#""up_mbps":100"#));
        assert!(json.contains(r#""type":"salamander""#));
    }

    #[test]
    fn test_outbound_deserialization() {
        let json = r#"{
            "type": "direct",
            "tag": "direct-out"
        }"#;

        let outbound: Outbound = serde_json::from_str(json).unwrap();
        match outbound {
            Outbound::Direct(d) => {
                assert_eq!(d.tag, Some("direct-out".to_string()));
            }
            _ => panic!("Expected Direct outbound"),
        }
    }

    #[test]
    fn test_vmess_outbound_deserialization() {
        let json = r#"{
            "type": "vmess",
            "tag": "vmess-out",
            "server": "example.com",
            "server_port": 443,
            "uuid": "test-uuid",
            "security": "auto",
            "alter_id": 0
        }"#;

        let outbound: Outbound = serde_json::from_str(json).unwrap();
        match outbound {
            Outbound::VMess(v) => {
                assert_eq!(v.tag, Some("vmess-out".to_string()));
                assert_eq!(v.uuid, Some("test-uuid".to_string()));
                assert_eq!(v.security, Some("auto".to_string()));
            }
            _ => panic!("Expected VMess outbound"),
        }
    }

    #[test]
    fn test_v2ray_transport_websocket() {
        let ws = V2RayTransport::WebSocket(WebSocketTransport {
            path: Some("/ws".to_string()),
            max_early_data: 2048,
            early_data_header_name: Some("Sec-WebSocket-Protocol".to_string()),
            ..Default::default()
        });

        let json = serde_json::to_string(&ws).unwrap();
        assert!(json.contains(r#""type":"ws""#));
        assert!(json.contains(r#""path":"/ws""#));
        assert!(json.contains(r#""max_early_data":2048"#));
    }

    #[test]
    fn test_v2ray_transport_grpc() {
        let grpc = V2RayTransport::Grpc(GrpcTransport {
            service_name: Some("TunService".to_string()),
            ..Default::default()
        });

        let json = serde_json::to_string(&grpc).unwrap();
        assert!(json.contains(r#""type":"grpc""#));
        assert!(json.contains(r#""service_name":"TunService""#));
    }

    #[test]
    fn test_multiplex_config() {
        let mux = OutboundMultiplex {
            enabled: true,
            protocol: Some("h2mux".to_string()),
            max_connections: Some(4),
            padding: true,
            ..Default::default()
        };

        let json = serde_json::to_string(&mux).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""protocol":"h2mux""#));
        assert!(json.contains(r#""max_connections":4"#));
    }

    #[test]
    fn test_direct_outbound_default_empty() {
        let outbound = DirectOutbound::default();
        let json = serde_json::to_string(&outbound).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_block_outbound_minimal() {
        let block = BlockOutbound::new("block");
        let outbound = Outbound::Block(block);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"block""#));
        assert!(json.contains(r#""tag":"block""#));
    }

    #[test]
    fn test_tuic_outbound_serialization() {
        let tuic = TuicOutbound {
            tag: Some("tuic-out".to_string()),
            server: Some("tuic.example.com".to_string()),
            server_port: Some(443),
            uuid: Some("test-uuid".to_string()),
            password: Some("password".to_string()),
            congestion_control: Some("bbr".to_string()),
            udp_relay_mode: Some("native".to_string()),
            ..Default::default()
        };

        let outbound = Outbound::Tuic(tuic);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"tuic""#));
        assert!(json.contains(r#""congestion_control":"bbr""#));
    }

    #[test]
    fn test_ssh_outbound_serialization() {
        let ssh = SshOutbound {
            tag: Some("ssh-out".to_string()),
            server: Some("ssh.example.com".to_string()),
            server_port: Some(22),
            user: Some("admin".to_string()),
            password: Some("password123".to_string()),
            ..Default::default()
        };

        let outbound = Outbound::Ssh(ssh);
        let json = serde_json::to_string(&outbound).unwrap();
        assert!(json.contains(r#""type":"ssh""#));
        assert!(json.contains(r#""user":"admin""#));
    }
}

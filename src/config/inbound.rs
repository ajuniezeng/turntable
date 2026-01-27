use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::shared::{InboundTlsConfig, ListenFields};
use crate::config::util::{is_false, is_zero_u32};

// ============================================================================
// Inbound Enum
// ============================================================================

/// Inbound configuration enum
///
/// Represents all available inbound types in sing-box.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Inbound {
    /// Direct inbound (tunnel server)
    Direct(DirectInbound),
    /// Mixed inbound (SOCKS4/4a/5 and HTTP)
    Mixed(MixedInbound),
    /// SOCKS inbound (SOCKS4/4a/5)
    #[serde(rename = "socks")]
    Socks(SocksInbound),
    /// HTTP inbound
    #[serde(rename = "http")]
    Http(HttpInbound),
    /// Shadowsocks inbound
    Shadowsocks(ShadowsocksInbound),
    /// VMess inbound
    #[serde(rename = "vmess")]
    VMess(VMessInbound),
    /// Trojan inbound
    Trojan(TrojanInbound),
    /// Naive inbound
    Naive(NaiveInbound),
    /// Hysteria inbound
    Hysteria(HysteriaInbound),
    /// ShadowTLS inbound
    #[serde(rename = "shadowtls")]
    ShadowTls(ShadowTlsInbound),
    /// TUIC inbound
    #[serde(rename = "tuic")]
    Tuic(TuicInbound),
    /// Hysteria2 inbound
    Hysteria2(Hysteria2Inbound),
    /// VLESS inbound
    #[serde(rename = "vless")]
    VLess(VLessInbound),
    /// AnyTLS inbound
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsInbound),
    /// TUN inbound
    Tun(TunInbound),
    /// Redirect inbound (Linux only)
    Redirect(RedirectInbound),
    /// TProxy inbound (Linux only)
    #[serde(rename = "tproxy")]
    TProxy(TProxyInbound),
}

// ============================================================================
// Common Types
// ============================================================================

/// User authentication configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct User {
    /// Username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// User with name field (for protocols like VMess)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NamedUser {
    /// User name/identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Password or authentication key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// VMess user configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VMessUser {
    /// User name/identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// VMess UUID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// Alter ID (0 = AEAD, >0 = legacy)
    #[serde(default, rename = "alterId", skip_serializing_if = "is_zero_u32")]
    pub alter_id: u32,
}

/// VLESS user configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VLessUser {
    /// User name/identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// VLESS UUID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// VLESS flow (e.g., "xtls-rprx-vision")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
}

/// Shadowsocks user configuration for multi-user mode
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowsocksUser {
    /// User name/identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Shadowsocks relay destination
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowsocksDestination {
    /// Destination name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// TUIC user configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TuicUser {
    /// User name/identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// TUIC UUID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,

    /// TUIC password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Multiplex configuration for inbound
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InboundMultiplex {
    /// Enable multiplex support
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Padding - reject non-padded connections if enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub padding: bool,

    /// TCP Brutal configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brutal: Option<TcpBrutal>,
}

/// TCP Brutal configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TcpBrutal {
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

/// V2Ray transport configuration
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

    /// Permit without stream (client only)
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

/// Fallback server configuration (for Trojan)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FallbackServer {
    /// Server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
}

// ============================================================================
// Inbound Types
// ============================================================================

/// Direct inbound configuration (tunnel server)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DirectInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Listen network: "tcp", "udp", or both if empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Override connection destination address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    /// Override connection destination port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,
}

/// Mixed inbound configuration (SOCKS4/4a/5 and HTTP)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MixedInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// SOCKS and HTTP users (no auth if empty)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,

    /// Automatically set system proxy
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_system_proxy: bool,
}

/// SOCKS inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SocksInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// SOCKS users (no auth if empty)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,
}

/// HTTP inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// HTTP users (no auth if empty)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Automatically set system proxy
    #[serde(default, skip_serializing_if = "is_false")]
    pub set_system_proxy: bool,
}

/// Shadowsocks inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowsocksInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Listen network: "tcp", "udp", or both if empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Encryption method (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Password (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Multi-user mode users
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<ShadowsocksUser>,

    /// Relay destinations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<ShadowsocksDestination>,

    /// Managed by SSM API
    #[serde(default, skip_serializing_if = "is_false")]
    pub managed: bool,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<InboundMultiplex>,
}

/// VMess inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VMessInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// VMess users (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<VMessUser>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<InboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,
}

/// Trojan inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrojanInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Trojan users (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<NamedUser>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Fallback server configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<FallbackServer>,

    /// Fallback servers for specific ALPN
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub fallback_for_alpn: HashMap<String, FallbackServer>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<InboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,
}

/// Naive inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NaiveInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Naive users (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<User>,

    /// Network type: "tcp" or "udp"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// Hysteria inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HysteriaInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Upload bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,

    /// Obfuscation password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,

    /// Hysteria users
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<HysteriaUser>,

    /// Authentication password (deprecated, use users)
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

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// Hysteria user configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HysteriaUser {
    /// User name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Authentication string
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_str: Option<String>,
}

/// ShadowTLS inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowTlsInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// ShadowTLS protocol version (1, 2, or 3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// ShadowTLS password (for v2/v3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// ShadowTLS users (for v3)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<NamedUser>,

    /// Handshake server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<ShadowTlsHandshake>,

    /// Handshake for specific server names
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub handshake_for_server_name: HashMap<String, ShadowTlsHandshake>,

    /// Strict mode
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_mode: bool,

    /// Detour to actual server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
}

/// ShadowTLS handshake configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ShadowTlsHandshake {
    /// Handshake server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Handshake server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,
}

/// TUIC inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TuicInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// TUIC users (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<TuicUser>,

    /// Congestion control algorithm: cubic, new_reno, bbr
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_control: Option<String>,

    /// Authentication timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_timeout: Option<String>,

    /// Zero RTT handshake
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_rtt_handshake: bool,

    /// Heartbeat interval
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<String>,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// Hysteria2 inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Hysteria2Inbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Upload bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,

    /// Download bandwidth in Mbps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,

    /// Obfuscation configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Hysteria2Obfs>,

    /// Hysteria2 users
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<NamedUser>,

    /// Ignore client bandwidth settings
    #[serde(default, skip_serializing_if = "is_false")]
    pub ignore_client_bandwidth: bool,

    /// TLS configuration (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Masquerade URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masquerade: Option<String>,

    /// Enable Brutal debug logging
    #[serde(default, skip_serializing_if = "is_false")]
    pub brutal_debug: bool,
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

/// VLESS inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VLessInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// VLESS users (required)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<VLessUser>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,

    /// Multiplex configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<InboundMultiplex>,

    /// V2Ray transport configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<V2RayTransport>,
}

/// AnyTLS inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AnyTlsInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// AnyTLS users
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<NamedUser>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InboundTlsConfig>,
}

/// TUN inbound configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Virtual device name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,

    /// IPv4 and IPv6 address prefixes (since 1.10.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address: Vec<String>,

    /// Maximum transmission unit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,

    /// Set default route to TUN
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_route: bool,

    /// Linux iproute2 table index (since 1.10.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iproute2_table_index: Option<u32>,

    /// Linux iproute2 rule start index (since 1.10.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iproute2_rule_index: Option<u32>,

    /// Use nftables for improved routing (since 1.10.0, Linux only)
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_redirect: bool,

    /// Connection input mark for auto_redirect (since 1.10.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_redirect_input_mark: Option<String>,

    /// Connection output mark for auto_redirect (since 1.10.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_redirect_output_mark: Option<String>,

    /// Connection reset mark for auto_redirect pre-matching (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_redirect_reset_mark: Option<String>,

    /// NFQueue number for auto_redirect pre-matching (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_redirect_nfqueue: Option<u32>,

    /// Exclude MPTCP connections (since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub exclude_mptcp: bool,

    /// Loopback addresses (since 1.12.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loopback_address: Vec<String>,

    /// Enforce strict routing rules
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict_route: bool,

    /// Custom routes (since 1.10.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_address: Vec<String>,

    /// Excluded routes (since 1.10.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_exclude_address: Vec<String>,

    /// Route address set from rule-sets (since 1.10.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_address_set: Vec<String>,

    /// Route exclude address set from rule-sets (since 1.10.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_exclude_address_set: Vec<String>,

    /// Enable endpoint-independent NAT (gvisor only)
    #[serde(default, skip_serializing_if = "is_false")]
    pub endpoint_independent_nat: bool,

    /// UDP NAT expiration time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// TCP/IP stack: system, gvisor, or mixed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,

    /// Include interfaces (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_interface: Vec<String>,

    /// Exclude interfaces (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_interface: Vec<String>,

    /// Include UIDs (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_uid: Vec<u32>,

    /// Include UID ranges (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_uid_range: Vec<String>,

    /// Exclude UIDs (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_uid: Vec<u32>,

    /// Exclude UID ranges (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_uid_range: Vec<String>,

    /// Include Android users (Android only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_android_user: Vec<u32>,

    /// Include Android packages (Android only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_package: Vec<String>,

    /// Exclude Android packages (Android only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_package: Vec<String>,

    /// Platform-specific settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<TunPlatform>,

    // Deprecated fields
    /// Deprecated: IPv4 prefix (use address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet4_address: Vec<String>,

    /// Deprecated: IPv6 prefix (use address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet6_address: Vec<String>,

    /// Deprecated: IPv4 routes (use route_address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet4_route_address: Vec<String>,

    /// Deprecated: IPv6 routes (use route_address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet6_route_address: Vec<String>,

    /// Deprecated: IPv4 route exclusions (use route_exclude_address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet4_route_exclude_address: Vec<String>,

    /// Deprecated: IPv6 route exclusions (use route_exclude_address instead)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inet6_route_exclude_address: Vec<String>,

    /// Deprecated: GSO (no longer effective)
    #[serde(default, skip_serializing_if = "is_false")]
    pub gso: bool,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,
}

/// TUN platform configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunPlatform {
    /// HTTP proxy settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_proxy: Option<TunHttpProxy>,
}

/// TUN HTTP proxy configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TunHttpProxy {
    /// Enable system HTTP proxy
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// HTTP proxy server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// HTTP proxy server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Hostnames that bypass the HTTP proxy
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bypass_domain: Vec<String>,

    /// Hostnames that use the HTTP proxy (Apple only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_domain: Vec<String>,
}

/// Redirect inbound configuration (Linux only)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RedirectInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,
}

/// TProxy inbound configuration (Linux only)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TProxyInbound {
    /// Tag of the inbound
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Listen fields
    #[serde(flatten)]
    pub listen: ListenFields,

    /// Listen network: "tcp", "udp", or both if empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ============================================================================
// Builder Implementations
// ============================================================================

impl DirectInbound {
    /// Create a new direct inbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set listen address and port
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }
}

impl MixedInbound {
    /// Create a new mixed inbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set listen address and port
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }

    /// Add a user
    pub fn add_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.push(User {
            username: Some(username.into()),
            password: Some(password.into()),
        });
        self
    }
}

impl SocksInbound {
    /// Create a new SOCKS inbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set listen address and port
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }

    /// Add a user
    pub fn add_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.push(User {
            username: Some(username.into()),
            password: Some(password.into()),
        });
        self
    }
}

impl HttpInbound {
    /// Create a new HTTP inbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set listen address and port
    pub fn listen(mut self, address: impl Into<String>, port: u16) -> Self {
        self.listen.listen = Some(address.into());
        self.listen.listen_port = Some(port);
        self
    }

    /// Add a user
    pub fn add_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.users.push(User {
            username: Some(username.into()),
            password: Some(password.into()),
        });
        self
    }
}

impl TunInbound {
    /// Create a new TUN inbound with tag
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: Some(tag.into()),
            ..Default::default()
        }
    }

    /// Set TUN addresses
    pub fn address(mut self, addresses: Vec<String>) -> Self {
        self.address = addresses;
        self
    }

    /// Enable auto route
    pub fn auto_route(mut self) -> Self {
        self.auto_route = true;
        self
    }

    /// Set stack type
    pub fn stack(mut self, stack: impl Into<String>) -> Self {
        self.stack = Some(stack.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixed_inbound_serialization() {
        let inbound = MixedInbound::new("mixed-in")
            .listen("127.0.0.1", 7890)
            .add_user("admin", "password");

        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""tag":"mixed-in""#));
        assert!(json.contains(r#""listen":"127.0.0.1""#));
        assert!(json.contains(r#""listen_port":7890"#));
        assert!(json.contains(r#""username":"admin""#));
    }

    #[test]
    fn test_inbound_enum_mixed() {
        let mixed = MixedInbound::new("mixed-in").listen("0.0.0.0", 1080);
        let inbound = Inbound::Mixed(mixed);

        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"mixed""#));
        assert!(json.contains(r#""tag":"mixed-in""#));
    }

    #[test]
    fn test_inbound_enum_socks() {
        let socks = SocksInbound::new("socks-in").listen("0.0.0.0", 1080);
        let inbound = Inbound::Socks(socks);

        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"socks""#));
    }

    #[test]
    fn test_inbound_enum_http() {
        let http = HttpInbound::new("http-in").listen("0.0.0.0", 8080);
        let inbound = Inbound::Http(http);

        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"http""#));
    }

    #[test]
    fn test_tun_inbound_serialization() {
        let tun = TunInbound::new("tun-in")
            .address(vec![
                "172.18.0.1/30".to_string(),
                "fdfe:dcba:9876::1/126".to_string(),
            ])
            .auto_route()
            .stack("system");

        let inbound = Inbound::Tun(tun);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"tun""#));
        assert!(json.contains(r#""auto_route":true"#));
        assert!(json.contains(r#""stack":"system""#));
    }

    #[test]
    fn test_vmess_inbound_serialization() {
        let vmess = VMessInbound {
            tag: Some("vmess-in".to_string()),
            users: vec![VMessUser {
                name: Some("user1".to_string()),
                uuid: Some("bf000d23-0752-40b4-affe-68f7707a9661".to_string()),
                alter_id: 0,
            }],
            ..Default::default()
        };

        let inbound = Inbound::VMess(vmess);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"vmess""#));
        assert!(json.contains(r#""uuid":"bf000d23-0752-40b4-affe-68f7707a9661""#));
    }

    #[test]
    fn test_trojan_inbound_serialization() {
        let trojan = TrojanInbound {
            tag: Some("trojan-in".to_string()),
            users: vec![NamedUser {
                name: Some("user1".to_string()),
                password: Some("secret123".to_string()),
            }],
            ..Default::default()
        };

        let inbound = Inbound::Trojan(trojan);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"trojan""#));
        assert!(json.contains(r#""password":"secret123""#));
    }

    #[test]
    fn test_shadowsocks_inbound_serialization() {
        let ss = ShadowsocksInbound {
            tag: Some("ss-in".to_string()),
            method: Some("2022-blake3-aes-128-gcm".to_string()),
            password: Some("8JCsPssfgS8tiRwiMlhARg==".to_string()),
            ..Default::default()
        };

        let inbound = Inbound::Shadowsocks(ss);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"shadowsocks""#));
        assert!(json.contains(r#""method":"2022-blake3-aes-128-gcm""#));
    }

    #[test]
    fn test_inbound_deserialization() {
        let json = r#"{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 7890,
            "users": [
                {"username": "admin", "password": "secret"}
            ]
        }"#;

        let inbound: Inbound = serde_json::from_str(json).unwrap();
        match inbound {
            Inbound::Mixed(m) => {
                assert_eq!(m.tag, Some("mixed-in".to_string()));
                assert_eq!(m.listen.listen, Some("127.0.0.1".to_string()));
                assert_eq!(m.listen.listen_port, Some(7890));
                assert_eq!(m.users.len(), 1);
            }
            _ => panic!("Expected Mixed inbound"),
        }
    }

    #[test]
    fn test_tun_inbound_deserialization() {
        let json = r#"{
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.18.0.1/30"],
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        }"#;

        let inbound: Inbound = serde_json::from_str(json).unwrap();
        match inbound {
            Inbound::Tun(t) => {
                assert_eq!(t.tag, Some("tun-in".to_string()));
                assert!(t.auto_route);
                assert!(t.strict_route);
                assert_eq!(t.stack, Some("mixed".to_string()));
            }
            _ => panic!("Expected Tun inbound"),
        }
    }

    #[test]
    fn test_v2ray_transport_serialization() {
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
    fn test_hysteria2_inbound_serialization() {
        let hy2 = Hysteria2Inbound {
            tag: Some("hy2-in".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(100),
            obfs: Some(Hysteria2Obfs {
                obfs_type: Some("salamander".to_string()),
                password: Some("obfs_password".to_string()),
            }),
            users: vec![NamedUser {
                name: Some("user1".to_string()),
                password: Some("password123".to_string()),
            }],
            ..Default::default()
        };

        let inbound = Inbound::Hysteria2(hy2);
        let json = serde_json::to_string(&inbound).unwrap();
        assert!(json.contains(r#""type":"hysteria2""#));
        assert!(json.contains(r#""up_mbps":100"#));
        assert!(json.contains(r#""type":"salamander""#));
    }

    #[test]
    fn test_direct_inbound_default_empty() {
        let inbound = DirectInbound::default();
        let json = serde_json::to_string(&inbound).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_multiplex_config() {
        let mux = InboundMultiplex {
            enabled: true,
            padding: true,
            brutal: Some(TcpBrutal {
                enabled: true,
                up_mbps: Some(100),
                down_mbps: Some(100),
            }),
        };

        let json = serde_json::to_string(&mux).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""padding":true"#));
        assert!(json.contains(r#""up_mbps":100"#));
    }
}

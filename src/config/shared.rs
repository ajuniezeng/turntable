//! Shared field structures for sing-box configuration.
//!
//! This module contains reusable field structures that are embedded in multiple
//! configuration types like outbounds, inbounds, endpoints, etc.

use serde::{Deserialize, Serialize};

use crate::config::serde_helpers::is_false;

// ============================================================================
// Common Types
// ============================================================================

/// Routing mark - can be integer or string hexadecimal
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum RoutingMark {
    /// Integer routing mark (e.g., 1234)
    Number(u32),
    /// String hexadecimal routing mark (e.g., "0x1234")
    Hex(String),
}

/// Domain resolver configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum DomainResolver {
    /// Simple server tag reference
    Tag(String),
    /// Full resolver configuration (same format as DNS route rule action)
    Config(DomainResolverConfig),
}

/// Domain resolver configuration (mirrors DNS route rule action without action field)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DomainResolverConfig {
    /// Target DNS server tag
    pub server: String,

    /// Domain strategy for this query
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,

    /// Disable cache for this query
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,

    /// Rewrite TTL in DNS responses
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,

    /// Client subnet for this query
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

/// Network strategy for selecting interfaces (since 1.11.0)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStrategy {
    /// Connect to default network or networks specified in network_type sequentially
    Default,
    /// Connect to all networks or networks specified in network_type concurrently
    Hybrid,
    /// Connect to default/preferred networks, try fallback networks when unavailable
    Fallback,
}

/// Network type for interface selection
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// Domain strategy for resolving domain names
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

// ============================================================================
// Dial Fields
// ============================================================================

/// Dial fields for outbound connections.
///
/// These fields are used by outbounds, endpoints, DNS servers, and NTP
/// to configure how connections are made.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DialFields {
    /// The tag of the upstream outbound.
    /// If enabled, all other fields will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    /// The network interface to bind to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,

    /// The IPv4 address to bind to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<String>,

    /// The IPv6 address to bind to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<String>,

    /// Do not reserve a port when binding (Linux only, since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub bind_address_no_port: bool,

    /// Set netfilter routing mark (Linux only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<RoutingMark>,

    /// Reuse listener address
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_addr: bool,

    /// Set network namespace (Linux only, since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns: Option<String>,

    /// Connect timeout in golang's Duration format
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<String>,

    /// Enable TCP Fast Open
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_fast_open: bool,

    /// Enable TCP Multi Path (Go 1.21 required)
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_multi_path: bool,

    /// Disable TCP keep alive (since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_tcp_keep_alive: bool,

    /// TCP keep alive initial period (default: "5m", since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<String>,

    /// TCP keep alive interval (default: "75s", since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<String>,

    /// Enable UDP fragmentation
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_fragment: bool,

    /// Domain resolver for resolving domain names (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolver>,

    /// Strategy for selecting network interfaces (since 1.11.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,

    /// Network types to use (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<NetworkType>,

    /// Fallback network types (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_network_type: Vec<NetworkType>,

    /// Fallback delay for RFC 6555 Fast Fallback (default: "300ms", since 1.11.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay: Option<String>,

    /// Deprecated: Domain strategy (deprecated in 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DomainStrategy>,
}

// ============================================================================
// Listen Fields
// ============================================================================

/// Listen fields for inbound connections.
///
/// These fields are used by inbounds to configure how they listen for connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ListenFields {
    /// Listen address (required)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Listen port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,

    /// The network interface to bind to (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,

    /// Set netfilter routing mark (Linux only, since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<RoutingMark>,

    /// Reuse listener address (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub reuse_addr: bool,

    /// Set network namespace (Linux only, since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns: Option<String>,

    /// Enable TCP Fast Open
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_fast_open: bool,

    /// Enable TCP Multi Path (Go 1.21 required)
    #[serde(default, skip_serializing_if = "is_false")]
    pub tcp_multi_path: bool,

    /// Disable TCP keep alive (since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_tcp_keep_alive: bool,

    /// TCP keep alive initial period (default: "5m", since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<String>,

    /// TCP keep alive interval (default: "75s")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<String>,

    /// Enable UDP fragmentation
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_fragment: bool,

    /// UDP NAT expiration time (default: "5m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// Forward connections to specified inbound tag
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    // Deprecated fields (deprecated in 1.11.0)
    /// Deprecated: Enable sniffing
    #[serde(default, skip_serializing_if = "is_false")]
    pub sniff: bool,

    /// Deprecated: Override destination with sniffed domain
    #[serde(default, skip_serializing_if = "is_false")]
    pub sniff_override_destination: bool,

    /// Deprecated: Sniffing timeout (default: "300ms")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniff_timeout: Option<String>,

    /// Deprecated: Domain strategy for resolving
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DomainStrategy>,

    /// Deprecated: Disable domain unmapping for UDP
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_disable_domain_unmapping: bool,
}

// ============================================================================
// TLS Fields
// ============================================================================

/// TLS configuration for inbound (server) connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InboundTlsConfig {
    /// Enable TLS
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Server name for SNI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// List of supported ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Minimum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    /// Maximum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,

    /// List of enabled TLS 1.0-1.2 cipher suites
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,

    /// Key exchange mechanisms (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub curve_preferences: Vec<String>,

    /// Server certificate chain in PEM format
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate: Vec<String>,

    /// Path to server certificate chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<String>,

    /// Client authentication type (since 1.13.0)
    /// Values: "no", "request", "require-any", "verify-if-given", "require-and-verify"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_authentication: Option<String>,

    /// Client certificate chain in PEM format (for server verification)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_certificate: Vec<String>,

    /// Paths to client certificate chains (for server verification)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_certificate_path: Vec<String>,

    /// SHA-256 hashes of client certificate public keys (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_certificate_public_key_sha256: Vec<String>,

    /// Server private key in PEM format
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key: Vec<String>,

    /// Path to server private key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,

    /// Enable kernel TLS transmit (Linux 5.1+, TLS 1.3 only, since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub kernel_tx: bool,

    /// Enable kernel TLS receive (Linux 5.1+, TLS 1.3 only, since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub kernel_rx: bool,

    /// ACME configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeConfig>,

    /// ECH (Encrypted Client Hello) configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<InboundEchConfig>,

    /// Reality configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<InboundRealityConfig>,
}

/// TLS configuration for outbound (client) connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboundTlsConfig {
    /// Enable TLS
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Do not send server name in ClientHello
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_sni: bool,

    /// Server name for verification and SNI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// Accept any server certificate (insecure)
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,

    /// List of supported ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Minimum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    /// Maximum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,

    /// List of enabled TLS 1.0-1.2 cipher suites
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,

    /// Key exchange mechanisms (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub curve_preferences: Vec<String>,

    /// Server certificate in PEM format (for pinning)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// Path to server certificate (for pinning)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<String>,

    /// SHA-256 hashes of server certificate public keys (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_public_key_sha256: Vec<String>,

    /// Client certificate chain in PEM format (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_certificate: Vec<String>,

    /// Path to client certificate chain (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_path: Option<String>,

    /// Client private key in PEM format (since 1.13.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_key: Vec<String>,

    /// Path to client private key (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,

    /// Fragment TLS handshakes (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub fragment: bool,

    /// Fallback delay for fragment (default: "500ms", since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_fallback_delay: Option<String>,

    /// Fragment into multiple TLS records (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub record_fragment: bool,

    /// ECH (Encrypted Client Hello) configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<OutboundEchConfig>,

    /// uTLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utls: Option<UtlsConfig>,

    /// Reality configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<OutboundRealityConfig>,
}

/// ACME configuration for automatic certificate management.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AcmeConfig {
    /// List of domains for certificate
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,

    /// Directory to store ACME data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_directory: Option<String>,

    /// Default server name when ClientHello ServerName is empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_server_name: Option<String>,

    /// Email address for ACME account
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// ACME CA provider: "letsencrypt", "zerossl", or custom URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Disable HTTP challenges
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_http_challenge: bool,

    /// Disable TLS-ALPN challenges
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_tls_alpn_challenge: bool,

    /// Alternate port for HTTP challenge (instead of 80)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative_http_port: Option<u16>,

    /// Alternate port for TLS-ALPN challenge (system must forward 443 to this)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative_tls_port: Option<u16>,

    /// External Account Binding
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_account: Option<ExternalAccount>,

    /// DNS01 challenge configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns01_challenge: Option<Dns01Challenge>,
}

/// External Account Binding for ACME.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ExternalAccount {
    /// Key identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// MAC key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_key: Option<String>,
}

/// ECH (Encrypted Client Hello) configuration for inbound (server).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InboundEchConfig {
    /// Enable ECH
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// ECH key in PEM format
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key: Vec<String>,

    /// Path to ECH key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,

    /// Deprecated: Enable PQ signature schemes (deprecated in 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub pq_signature_schemes_enabled: bool,

    /// Deprecated: Disable dynamic record sizing (deprecated in 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub dynamic_record_sizing_disabled: bool,
}

/// ECH (Encrypted Client Hello) configuration for outbound (client).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboundEchConfig {
    /// Enable ECH
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// ECH configuration in PEM format
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config: Vec<String>,

    /// Path to ECH configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,

    /// Override domain for ECH HTTPS record queries (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_server_name: Option<String>,

    /// Deprecated: Enable PQ signature schemes (deprecated in 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub pq_signature_schemes_enabled: bool,

    /// Deprecated: Disable dynamic record sizing (deprecated in 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub dynamic_record_sizing_disabled: bool,
}

/// uTLS configuration for TLS fingerprint resistance.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UtlsConfig {
    /// Enable uTLS
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Fingerprint to use: chrome, firefox, edge, safari, 360, qq, ios, android, random, randomized
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// Reality configuration for inbound (server).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InboundRealityConfig {
    /// Enable Reality
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Handshake server configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<RealityHandshake>,

    /// Private key (generated by `sing-box generate reality-keypair`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// Short ID list (hex strings, 0-8 digits each)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub short_id: Vec<String>,

    /// Maximum time difference between server and client
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_time_difference: Option<String>,
}

/// Reality handshake server configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RealityHandshake {
    /// Handshake server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Handshake server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Dial fields for handshake connection
    #[serde(flatten)]
    pub dial: DialFields,
}

/// Reality configuration for outbound (client).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OutboundRealityConfig {
    /// Enable Reality
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Public key (generated by `sing-box generate reality-keypair`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,

    /// Short ID (hex string, 0-8 digits)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

// ============================================================================
// DNS01 Challenge Fields
// ============================================================================

/// DNS01 challenge configuration for ACME.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum Dns01Challenge {
    /// Alibaba Cloud DNS
    #[serde(rename = "alidns")]
    AliDns(AliDnsChallenge),

    /// Cloudflare
    Cloudflare(CloudflareChallenge),

    /// ACME-DNS (since 1.13.0)
    #[serde(rename = "acmedns")]
    AcmeDns(AcmeDnsChallenge),
}

/// Alibaba Cloud DNS challenge configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AliDnsChallenge {
    /// Access Key ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,

    /// Access Key Secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_secret: Option<String>,

    /// Region ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_id: Option<String>,

    /// Security Token for STS temporary credentials (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_token: Option<String>,
}

/// Cloudflare DNS challenge configuration.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CloudflareChallenge {
    /// API token with DNS:Edit permission
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,

    /// Optional API token with Zone:Read permission (since 1.13.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_token: Option<String>,
}

/// ACME-DNS challenge configuration (since 1.13.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AcmeDnsChallenge {
    /// ACME-DNS username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// ACME-DNS password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// ACME-DNS subdomain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,

    /// ACME-DNS server URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

// ============================================================================
// Pre-match Fields
// ============================================================================

/// Pre-match is rule matching that runs before the connection is established.
///
/// When TUN receives a connection request, the connection has not yet been established,
/// so no connection data can be read. In this phase, sing-box runs the routing rules
/// in pre-match mode.
///
/// Supported actions:
/// - `reject`: Reject with TCP RST / ICMP unreachable
/// - `route`: Route ICMP connections to specified outbound
/// - `bypass`: Bypass sing-box and connect directly at kernel level (since 1.13.0)
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum PreMatchAction {
    /// Reject with TCP RST / ICMP unreachable
    Reject(PreMatchReject),

    /// Route ICMP connections to specified outbound
    Route(PreMatchRoute),

    /// Bypass sing-box (Linux with auto_redirect, since 1.13.0)
    Bypass(PreMatchBypass),
}

/// Pre-match reject action.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PreMatchReject {
    /// Reject method
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Disable automatic drop after repeated triggers
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
}

/// Pre-match route action.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PreMatchRoute {
    /// Target outbound tag
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

/// Pre-match bypass action (since 1.13.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PreMatchBypass {
    /// Target outbound tag (optional)
    /// If not specified, only matches in pre-match from auto redirect
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dial_fields_default_serializes_empty() {
        let dial = DialFields::default();
        let json = serde_json::to_string(&dial).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_dial_fields_with_values() {
        let dial = DialFields {
            detour: Some("proxy".to_string()),
            bind_interface: Some("eth0".to_string()),
            tcp_fast_open: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&dial).unwrap();
        assert!(json.contains(r#""detour":"proxy""#));
        assert!(json.contains(r#""bind_interface":"eth0""#));
        assert!(json.contains(r#""tcp_fast_open":true"#));
    }

    #[test]
    fn test_listen_fields_default_serializes_empty() {
        let listen = ListenFields::default();
        let json = serde_json::to_string(&listen).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_listen_fields_with_values() {
        let listen = ListenFields {
            listen: Some("0.0.0.0".to_string()),
            listen_port: Some(1080),
            tcp_fast_open: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&listen).unwrap();
        assert!(json.contains(r#""listen":"0.0.0.0""#));
        assert!(json.contains(r#""listen_port":1080"#));
    }

    #[test]
    fn test_outbound_tls_default_serializes_empty() {
        let tls = OutboundTlsConfig::default();
        let json = serde_json::to_string(&tls).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_outbound_tls_with_values() {
        let tls = OutboundTlsConfig {
            enabled: true,
            server_name: Some("example.com".to_string()),
            insecure: false,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&tls).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""server_name":"example.com""#));
        assert!(json.contains(r#""alpn":["h2","http/1.1"]"#));
        // insecure is false, should be skipped
        assert!(!json.contains("insecure"));
    }

    #[test]
    fn test_inbound_tls_with_acme() {
        let tls = InboundTlsConfig {
            enabled: true,
            acme: Some(AcmeConfig {
                domain: vec!["example.com".to_string()],
                email: Some("admin@example.com".to_string()),
                provider: Some("letsencrypt".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&tls).unwrap();
        assert!(json.contains("acme"));
        assert!(json.contains("example.com"));
        assert!(json.contains("letsencrypt"));
    }

    #[test]
    fn test_routing_mark_number() {
        let mark = RoutingMark::Number(1234);
        let json = serde_json::to_string(&mark).unwrap();
        assert_eq!(json, "1234");
    }

    #[test]
    fn test_routing_mark_hex() {
        let mark = RoutingMark::Hex("0x1234".to_string());
        let json = serde_json::to_string(&mark).unwrap();
        assert_eq!(json, r#""0x1234""#);
    }

    #[test]
    fn test_domain_resolver_tag() {
        let resolver = DomainResolver::Tag("local".to_string());
        let json = serde_json::to_string(&resolver).unwrap();
        assert_eq!(json, r#""local""#);
    }

    #[test]
    fn test_domain_resolver_config() {
        let resolver = DomainResolver::Config(DomainResolverConfig {
            server: "google".to_string(),
            strategy: Some("prefer_ipv4".to_string()),
            ..Default::default()
        });
        let json = serde_json::to_string(&resolver).unwrap();
        assert!(json.contains(r#""server":"google""#));
        assert!(json.contains(r#""strategy":"prefer_ipv4""#));
    }

    #[test]
    fn test_network_strategy_serialization() {
        let strategy = NetworkStrategy::Fallback;
        let json = serde_json::to_string(&strategy).unwrap();
        assert_eq!(json, r#""fallback""#);
    }

    #[test]
    fn test_network_type_serialization() {
        let net_type = NetworkType::Wifi;
        let json = serde_json::to_string(&net_type).unwrap();
        assert_eq!(json, r#""wifi""#);
    }

    #[test]
    fn test_dns01_challenge_cloudflare() {
        let challenge = Dns01Challenge::Cloudflare(CloudflareChallenge {
            api_token: Some("token123".to_string()),
            zone_token: Some("zone456".to_string()),
        });
        let json = serde_json::to_string(&challenge).unwrap();
        assert!(json.contains(r#""provider":"cloudflare""#));
        assert!(json.contains(r#""api_token":"token123""#));
        assert!(json.contains(r#""zone_token":"zone456""#));
    }

    #[test]
    fn test_dns01_challenge_alidns() {
        let challenge = Dns01Challenge::AliDns(AliDnsChallenge {
            access_key_id: Some("id".to_string()),
            access_key_secret: Some("secret".to_string()),
            region_id: Some("cn-hangzhou".to_string()),
            security_token: None,
        });
        let json = serde_json::to_string(&challenge).unwrap();
        assert!(json.contains(r#""provider":"alidns""#));
        assert!(json.contains(r#""access_key_id":"id""#));
    }

    #[test]
    fn test_utls_config() {
        let utls = UtlsConfig {
            enabled: true,
            fingerprint: Some("chrome".to_string()),
        };
        let json = serde_json::to_string(&utls).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""fingerprint":"chrome""#));
    }

    #[test]
    fn test_reality_outbound() {
        let reality = OutboundRealityConfig {
            enabled: true,
            public_key: Some("jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".to_string()),
            short_id: Some("0123456789abcdef".to_string()),
        };
        let json = serde_json::to_string(&reality).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains("public_key"));
        assert!(json.contains("short_id"));
    }

    #[test]
    fn test_dial_fields_deserialization() {
        let json = r#"{"detour": "proxy", "tcp_fast_open": true}"#;
        let dial: DialFields = serde_json::from_str(json).unwrap();
        assert_eq!(dial.detour, Some("proxy".to_string()));
        assert!(dial.tcp_fast_open);
    }

    #[test]
    fn test_domain_strategy_serialization() {
        let strategy = DomainStrategy::PreferIpv4;
        let json = serde_json::to_string(&strategy).unwrap();
        assert_eq!(json, r#""prefer_ipv4""#);
    }
}

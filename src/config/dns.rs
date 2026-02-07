use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::config::serde_helpers::{is_false, string_or_vec};
use crate::config::shared::DialFields;

/// DNS configuration for sing-box
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Dns {
    /// List of DNS servers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,

    /// List of DNS rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,

    /// Default DNS server tag. The first server will be used if empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#final: Option<String>,

    /// Default domain strategy for resolving domain names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,

    /// Disable DNS cache
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,

    /// Disable DNS cache expiration
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_expire: bool,

    /// Make each DNS server's cache independent
    #[serde(default, skip_serializing_if = "is_false")]
    pub independent_cache: bool,

    /// LRU cache capacity. Values less than 1024 will be ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<u32>,

    /// Store reverse mapping of IP addresses for domain lookup during routing
    #[serde(default, skip_serializing_if = "is_false")]
    pub reverse_mapping: bool,

    /// Append edns0-subnet OPT extra record with specified IP prefix to every query
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,

    /// FakeIP configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fakeip: Option<FakeIp>,
}

/// Domain resolution strategy
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

/// DNS Server configuration - supports multiple server types
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsServer {
    /// Legacy DNS server (deprecated in 1.12.0)
    #[serde(rename = "")]
    Legacy(LegacyDnsServer),

    /// Local DNS server (system resolver)
    Local(LocalDnsServer),

    /// Hosts file based DNS server
    Hosts(HostsDnsServer),

    /// DNS over TCP
    Tcp(TcpDnsServer),

    /// DNS over UDP
    Udp(UdpDnsServer),

    /// DNS over TLS (DoT)
    Tls(TlsDnsServer),

    /// DNS over QUIC (DoQ)
    Quic(QuicDnsServer),

    /// DNS over HTTPS (DoH)
    Https(HttpsDnsServer),

    /// DNS over HTTP/3
    H3(H3DnsServer),

    /// DHCP DNS server
    Dhcp(DhcpDnsServer),

    /// FakeIP DNS server
    #[serde(rename = "fakeip")]
    FakeIp(FakeIpDnsServer),

    /// Tailscale DNS server
    Tailscale(TailscaleDnsServer),

    /// Resolved DNS server
    Resolved(ResolvedDnsServer),
}

/// Legacy DNS server configuration (deprecated in 1.12.0)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct LegacyDnsServer {
    pub tag: String,

    /// DNS server address (e.g., "8.8.8.8", "tls://dns.google", "https://1.1.1.1/dns-query")
    pub address: String,

    /// Tag of another server to resolve domain names in the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_resolver: Option<String>,

    /// Domain strategy for resolving the domain name in the address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_strategy: Option<Strategy>,

    /// Default domain strategy for resolving domain names
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,

    /// Tag of an outbound for connecting to the DNS server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,

    /// Append edns0-subnet OPT extra record
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

/// Local DNS server (system resolver)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct LocalDnsServer {
    pub tag: String,

    /// When enabled, local DNS server will resolve DNS by dialing itself whenever possible (since 1.13.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefer_go: bool,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// Hosts file based DNS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HostsDnsServer {
    pub tag: String,

    /// Paths to hosts files (defaults to system hosts file)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,

    /// Predefined hosts entries
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predefined: Option<HashMap<String, Vec<String>>>,
}

/// DNS over TCP server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TcpDnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 53)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// DNS over UDP server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UdpDnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 53)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// TLS configuration for DNS servers
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TlsConfig {
    /// Enable TLS
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Server name for SNI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    /// Disable SNI
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_sni: bool,

    /// Insecure skip verify
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure: bool,

    /// ALPN protocols
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,

    /// Minimum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,

    /// Maximum TLS version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,

    /// Cipher suites
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<String>,

    /// Certificate path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<String>,

    /// Certificate content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

/// DNS over TLS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TlsDnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 853)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// DNS over QUIC server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct QuicDnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 853)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// DNS over HTTPS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HttpsDnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 443)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// URL path (default: /dns-query)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Additional HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// DNS over HTTP/3 server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct H3DnsServer {
    pub tag: String,

    /// DNS server address
    pub server: String,

    /// DNS server port (default: 443)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// URL path (default: /dns-query)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Additional HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// DHCP DNS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DhcpDnsServer {
    pub tag: String,

    /// Network interface (e.g., "en0", "auto")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,

    #[serde(flatten)]
    pub dial: DialFields,
}

/// FakeIP DNS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FakeIpDnsServer {
    pub tag: String,

    /// IPv4 address range for FakeIP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_range: Option<String>,

    /// IPv6 address range for FakeIP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_range: Option<String>,
}

/// Tailscale DNS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TailscaleDnsServer {
    pub tag: String,

    /// The tag of the Tailscale Endpoint (required)
    pub endpoint: String,

    /// Accept default DNS resolvers for fallback queries in addition to MagicDNS
    #[serde(default, skip_serializing_if = "is_false")]
    pub accept_default_resolvers: bool,
}

/// Resolved DNS server
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResolvedDnsServer {
    pub tag: String,

    /// The tag of the Resolved Service (required)
    pub service: String,

    /// Accept default DNS resolvers for fallback queries in addition to matching domains
    #[serde(default, skip_serializing_if = "is_false")]
    pub accept_default_resolvers: bool,
}

/// FakeIP configuration (deprecated in 1.12.0)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FakeIp {
    /// Enable FakeIP service
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// IPv4 address range for FakeIP (default: 198.18.0.0/15)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_range: Option<String>,

    /// IPv6 address range for FakeIP (default: fc00::/18)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_range: Option<String>,
}

/// DNS Rule configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum DnsRule {
    /// Logical rule combining multiple rules (must be tried first by serde
    /// because DefaultDnsRule has all-optional fields and would match anything)
    Logical(LogicalDnsRule),

    /// Default rule with match conditions
    Default(Box<DefaultDnsRule>),
}

/// Default DNS rule with match conditions
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DefaultDnsRule {
    // Match conditions
    /// Match inbound tags
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub inbound: Vec<String>,

    /// Match IP version (4 or 6)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,

    /// Match DNS query type
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "query_type_string_or_vec"
    )]
    pub query_type: Vec<QueryType>,

    /// Match network type (tcp or udp)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Match authenticated user
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub auth_user: Vec<String>,

    /// Match sniffed protocol
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub protocol: Vec<String>,

    /// Match full domain
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub domain: Vec<String>,

    /// Match domain suffix
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub domain_suffix: Vec<String>,

    /// Match domain keyword
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub domain_keyword: Vec<String>,

    /// Match domain regex
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub domain_regex: Vec<String>,

    /// Match source IP CIDR
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_ip_cidr: Vec<String>,

    /// Match non-public source IP
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_ip_is_private: bool,

    /// Match IP CIDR with query response
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub ip_cidr: Vec<String>,

    /// Match private IP with query response
    #[serde(default, skip_serializing_if = "is_false")]
    pub ip_is_private: bool,

    /// Match any IP with query response
    #[serde(default, skip_serializing_if = "is_false")]
    pub ip_accept_any: bool,

    /// Match source port
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,

    /// Match source port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_port_range: Vec<String>,

    /// Match destination port
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,

    /// Match destination port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub port_range: Vec<String>,

    /// Match process name
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_name: Vec<String>,

    /// Match process path
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_path: Vec<String>,

    /// Match process path regex
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_path_regex: Vec<String>,

    /// Match Android package name
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub package_name: Vec<String>,

    /// Match user name (Linux only)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub user: Vec<String>,

    /// Match user ID (Linux only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_id: Vec<u32>,

    /// Match Clash mode
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,

    /// Match network type (wifi, cellular, ethernet, other)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub network_type: Vec<String>,

    /// Match if network is considered expensive
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_expensive: bool,

    /// Match if network is in Low Data Mode
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_constrained: bool,

    /// Match interface address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_address: Option<HashMap<String, Vec<String>>>,

    /// Match network interface address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_interface_address: Option<HashMap<String, Vec<String>>>,

    /// Match default interface address
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub default_interface_address: Vec<String>,

    /// Match WiFi SSID
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub wifi_ssid: Vec<String>,

    /// Match WiFi BSSID
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub wifi_bssid: Vec<String>,

    /// Match rule-set
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub rule_set: Vec<String>,

    /// Make ip_cidr rules in rule-sets match the source IP
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ip_cidr_match_source: bool,

    /// Make ip_cidr rules in rule-sets accept empty query response
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ip_cidr_accept_empty: bool,

    /// Invert match result
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,

    /// Match outbound tags (deprecated in 1.12.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub outbound: Vec<String>,

    // Action fields
    /// Rule action
    #[serde(flatten)]
    pub action: DnsRuleAction,

    // Deprecated fields
    /// Deprecated: Use rule_set_ip_cidr_match_source instead
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ipcidr_match_source: bool,

    /// Deprecated: Match geosite
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub geosite: Vec<String>,

    /// Deprecated: Match source GeoIP
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_geoip: Vec<String>,

    /// Deprecated: Match GeoIP with query response
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub geoip: Vec<String>,
}

/// Helper enum for deserializing query_type fields that can be either a single value or an array.
#[derive(Deserialize)]
#[serde(untagged)]
enum QueryTypeOrVec {
    Single(QueryType),
    Multiple(Vec<QueryType>),
}

/// Deserializes a query_type field that can be either a single value or an array.
fn query_type_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<QueryType>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match QueryTypeOrVec::deserialize(deserializer)? {
        QueryTypeOrVec::Single(s) => Ok(vec![s]),
        QueryTypeOrVec::Multiple(v) => Ok(v),
    }
}

/// Query type - can be integer or string
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum QueryType {
    /// Query type as integer (e.g., 1 for A, 28 for AAAA)
    Number(u16),
    /// Query type as string (e.g., "A", "AAAA", "HTTPS")
    Name(String),
}

/// Logical DNS rule combining multiple rules
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogicalDnsRule {
    /// Rule type marker
    pub r#type: String, // "logical"

    /// Logical mode: "and" or "or"
    pub mode: LogicalMode,

    /// Included rules
    pub rules: Vec<DnsRule>,

    /// Rule action
    #[serde(flatten)]
    pub action: DnsRuleAction,
}

/// Logical mode for combining rules
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogicalMode {
    And,
    Or,
}

/// DNS rule action
/// Supports both legacy format (just `server` field) and new format (`action` tag)
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum DnsRuleAction {
    /// Tagged action with explicit `action` field (try first since it has discriminator)
    Tagged(TaggedDnsRuleAction),

    /// Legacy route action - just has `server` field without `action` tag
    Legacy(LegacyRouteAction),
}

/// Legacy route action for backward compatibility
/// Used when DNS rule has `server` field but no `action` tag
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LegacyRouteAction {
    /// Target DNS server tag (required for legacy format)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,

    /// Domain strategy for this query
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,

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

/// Tagged DNS rule action with explicit `action` field
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum TaggedDnsRuleAction {
    /// Route to a DNS server
    Route(RouteAction),

    /// Set route options
    #[serde(rename = "route-options")]
    RouteOptions(RouteOptionsAction),

    /// Reject the DNS request
    Reject(RejectAction),

    /// Respond with predefined DNS records
    Predefined(PredefinedAction),
}

impl Default for DnsRuleAction {
    fn default() -> Self {
        DnsRuleAction::Legacy(LegacyRouteAction {
            server: String::new(),
            strategy: None,
            disable_cache: false,
            rewrite_ttl: None,
            client_subnet: None,
        })
    }
}

/// Route action for DNS rules
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RouteAction {
    /// Target DNS server tag
    pub server: String,

    /// Domain strategy for this query
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,

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

/// Route options action for DNS rules
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RouteOptionsAction {
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

/// Reject action for DNS rules
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RejectAction {
    /// Reject method: "default" (REFUSED) or "drop"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<RejectMethod>,

    /// If not enabled, method will be temporarily overwritten to drop after 50 triggers in 30s
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
}

/// Reject method for DNS rules
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RejectMethod {
    Default,
    Drop,
}

/// Predefined action for DNS rules
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PredefinedAction {
    /// Response code (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<RCode>,

    /// List of text DNS records to respond as answers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<String>,

    /// List of text DNS records to respond as name servers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<String>,

    /// List of text DNS records to respond as extra records
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
}

/// DNS response code
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RCode {
    /// No error
    #[serde(rename = "NOERROR")]
    NoError,
    /// Format error (bad request)
    #[serde(rename = "FORMERR")]
    FormErr,
    /// Server failure
    #[serde(rename = "SERVFAIL")]
    ServFail,
    /// Non-existent domain (not found)
    #[serde(rename = "NXDOMAIN")]
    NxDomain,
    /// Not implemented
    #[serde(rename = "NOTIMP")]
    NotImp,
    /// Query refused
    #[serde(rename = "REFUSED")]
    Refused,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_serialization() {
        let strategy = Strategy::PreferIpv4;
        let json = serde_json::to_string(&strategy).unwrap();
        assert_eq!(json, r#""prefer_ipv4""#);
    }

    #[test]
    fn test_dns_default() {
        let dns = Dns::default();
        let json = serde_json::to_string(&dns).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_dns_server_legacy() {
        let server = LegacyDnsServer {
            tag: "google".to_string(),
            address: "8.8.8.8".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&server).unwrap();
        assert!(json.contains(r#""tag":"google""#));
        assert!(json.contains(r#""address":"8.8.8.8""#));
    }

    #[test]
    fn test_dns_rule_with_reject_action() {
        let json = r#"{"rule_set": "AWAvenue-Ads-Rule", "action": "reject"}"#;
        let result: Result<DefaultDnsRule, _> = serde_json::from_str(json);
        println!("Result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse DNS rule with reject action: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_dns_rule_with_server_only() {
        let json = r#"{"clash_mode": "global", "server": "fakedns"}"#;
        let result: Result<DefaultDnsRule, _> = serde_json::from_str(json);
        println!("Result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse DNS rule with server only: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_dns_rule_action_tagged_reject() {
        let json = r#"{"action": "reject"}"#;
        let result: Result<DnsRuleAction, _> = serde_json::from_str(json);
        println!("Result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse DnsRuleAction reject: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_dns_rule_action_legacy_server() {
        let json = r#"{"server": "fakedns"}"#;
        let result: Result<DnsRuleAction, _> = serde_json::from_str(json);
        println!("Result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse DnsRuleAction legacy: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_logical_dns_rule_roundtrip() {
        let json = r#"{
            "type": "logical",
            "mode": "and",
            "rules": [
                { "query_type": ["A", "AAAA"] },
                { "rule_set": "geosite-geolocation-!cn" }
            ],
            "server": "secure"
        }"#;

        let rule: DnsRule = serde_json::from_str(json).unwrap();

        // Must be deserialized as Logical, not Default
        assert!(
            matches!(rule, DnsRule::Logical(_)),
            "Expected DnsRule::Logical, got DnsRule::Default"
        );

        // Round-trip: mode and rules must survive serialization
        let output = serde_json::to_string(&rule).unwrap();
        assert!(
            output.contains("\"mode\""),
            "Missing 'mode' in output: {output}"
        );
        assert!(
            output.contains("\"rules\""),
            "Missing 'rules' in output: {output}"
        );
        assert!(
            output.contains("\"server\""),
            "Missing 'server' in output: {output}"
        );
    }
}

//! Subscription and Protocol Parsing Module
//!
//! This module provides functionality for:
//! - Detecting subscription content types (Sing-box JSON, Base64 URI list, Clash YAML)
//! - Decoding content (handling Base64 encoding with various line break scenarios)
//! - Parsing protocol URIs (ss://, vmess://, vless://, trojan://, hysteria2://, tuic://)
//! - Dynamic dispatch to appropriate parsers based on detected type

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use tracing::{debug, trace, warn};
use url::Url;

use crate::config::outbound::{
    GrpcTransport, Hysteria2Obfs, Hysteria2Outbound, Outbound, ShadowsocksOutbound, TrojanOutbound,
    TuicOutbound, V2RayTransport, VLessOutbound, VMessOutbound, WebSocketTransport,
};
use crate::config::shared::{DialFields, OutboundRealityConfig, OutboundTlsConfig, UtlsConfig};

// ============================================================================
// Subscription Type Detection
// ============================================================================

/// Detected subscription content type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionType {
    /// Sing-box native JSON format (contains "outbounds" array)
    SingBoxJson,
    /// Base64 encoded URI list
    Base64UriList,
    /// Plain text URI list (one URI per line)
    PlainUriList,
    /// Clash YAML format
    ClashYaml,
    /// Unknown format
    Unknown,
}

impl std::fmt::Display for SubscriptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionType::SingBoxJson => write!(f, "Sing-box JSON"),
            SubscriptionType::Base64UriList => write!(f, "Base64 URI List"),
            SubscriptionType::PlainUriList => write!(f, "Plain URI List"),
            SubscriptionType::ClashYaml => write!(f, "Clash YAML"),
            SubscriptionType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detects the type of subscription content
pub fn detect_subscription_type(content: &str) -> SubscriptionType {
    let trimmed = content.trim();
    let content_preview: String = trimmed.chars().take(100).collect();
    debug!(
        "Detecting subscription type, content length: {} bytes, preview: {:?}...",
        content.len(),
        content_preview
    );

    // Check for Sing-box JSON format
    if is_singbox_json(trimmed) {
        debug!("Detected Sing-box JSON format (starts with '{{' and contains '\"outbounds\"')");
        return SubscriptionType::SingBoxJson;
    }

    // Check for Clash YAML format
    if is_clash_yaml(trimmed) {
        debug!("Detected Clash YAML format (contains proxy definitions)");
        return SubscriptionType::ClashYaml;
    }

    // Check for plain URI list (starts with protocol://)
    if is_plain_uri_list(trimmed) {
        let first_line = trimmed.lines().next().unwrap_or("");
        debug!(
            "Detected plain URI list format, first line: {:?}",
            first_line
        );
        return SubscriptionType::PlainUriList;
    }

    // Check for Base64 encoded content
    if is_base64_content(trimmed) {
        debug!("Detected Base64 encoded URI list format");
        return SubscriptionType::Base64UriList;
    }

    debug!("Unable to detect subscription format");
    SubscriptionType::Unknown
}

/// Checks if content is Sing-box JSON format
fn is_singbox_json(content: &str) -> bool {
    // Must start with { and be valid-ish JSON with "outbounds"
    let trimmed = content.trim();
    if !trimmed.starts_with('{') {
        return false;
    }

    // Quick check for "outbounds" key
    trimmed.contains("\"outbounds\"")
}

/// Checks if content is Clash YAML format
fn is_clash_yaml(content: &str) -> bool {
    let trimmed = content.trim();

    // Clash configs typically start with these keys
    trimmed.starts_with("proxies:")
        || trimmed.starts_with("proxy-groups:")
        || trimmed.starts_with("port:")
        || (trimmed.contains("proxies:") && trimmed.contains("- name:"))
}

/// Checks if content is a plain URI list
fn is_plain_uri_list(content: &str) -> bool {
    let first_line = content.lines().next().unwrap_or("").trim();

    // Check if first line looks like a proxy URI
    is_proxy_uri(first_line)
}

/// Checks if a string looks like a proxy URI
fn is_proxy_uri(s: &str) -> bool {
    let protocols = [
        "ss://",
        "ssr://",
        "vmess://",
        "vless://",
        "trojan://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "naive+https://",
        "socks://",
        "socks5://",
        "http://",
        "https://",
    ];

    protocols.iter().any(|p| s.starts_with(p))
}

/// Checks if content appears to be Base64 encoded
fn is_base64_content(content: &str) -> bool {
    let trimmed = content.trim();

    // Empty content is not Base64
    if trimmed.is_empty() {
        return false;
    }

    // Base64 content should only contain valid Base64 characters (plus optional whitespace)
    let cleaned: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();

    // Must have reasonable length
    if cleaned.is_empty() || cleaned.len() < 4 {
        return false;
    }

    // Check if all characters are valid Base64
    let is_valid_base64 = cleaned.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });

    if !is_valid_base64 {
        return false;
    }

    // Try to decode and see if it looks like URIs
    if let Ok(decoded) = decode_base64(&cleaned)
        && let Ok(decoded_str) = String::from_utf8(decoded)
    {
        // Check if decoded content contains proxy URIs
        return decoded_str.lines().any(|line| is_proxy_uri(line.trim()));
    }

    false
}

// ============================================================================
// Content Decoding
// ============================================================================

/// Decodes Base64 content, trying multiple variants
pub fn decode_base64(content: &str) -> Result<Vec<u8>> {
    // Remove all whitespace (handles line breaks within Base64)
    let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    trace!(
        "Attempting Base64 decode, cleaned length: {} bytes",
        cleaned.len()
    );

    // Try standard Base64 first
    if let Ok(decoded) = STANDARD.decode(&cleaned) {
        trace!("Decoded using standard Base64");
        return Ok(decoded);
    }

    // Try URL-safe Base64
    if let Ok(decoded) = URL_SAFE.decode(&cleaned) {
        trace!("Decoded using URL-safe Base64");
        return Ok(decoded);
    }

    // Try URL-safe Base64 without padding
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&cleaned) {
        trace!("Decoded using URL-safe Base64 without padding");
        return Ok(decoded);
    }

    // Try with padding added if needed
    let padded = add_base64_padding(&cleaned);
    if let Ok(decoded) = STANDARD.decode(&padded) {
        trace!("Decoded using standard Base64 with added padding");
        return Ok(decoded);
    }
    if let Ok(decoded) = URL_SAFE.decode(&padded) {
        trace!("Decoded using URL-safe Base64 with added padding");
        return Ok(decoded);
    }

    bail!("Failed to decode Base64 content")
}

/// Adds proper padding to Base64 string if missing
fn add_base64_padding(s: &str) -> String {
    let mut result = s.to_string();
    while !result.len().is_multiple_of(4) {
        result.push('=');
    }
    result
}

/// Decodes subscription content, automatically handling Base64 if needed
pub fn decode_subscription_content(content: &str) -> Result<String> {
    let subscription_type = detect_subscription_type(content);

    match subscription_type {
        SubscriptionType::Base64UriList => {
            let decoded = decode_base64(content.trim())?;
            String::from_utf8(decoded).context("Decoded Base64 content is not valid UTF-8")
        }
        _ => Ok(content.to_string()),
    }
}

// ============================================================================
// Protocol Parser Trait
// ============================================================================

/// Trait for parsing individual protocol URIs
pub trait ProtocolParser: Send + Sync {
    /// Returns the protocol scheme this parser handles (e.g., "ss", "vmess")
    fn scheme(&self) -> &str;

    /// Parses a URI string into an Outbound configuration
    fn parse(&self, uri: &str) -> Result<Outbound>;

    /// Checks if this parser can handle the given URI
    fn can_parse(&self, uri: &str) -> bool {
        uri.starts_with(&format!("{}://", self.scheme()))
    }
}

// ============================================================================
// Protocol Registry
// ============================================================================

/// Registry for protocol parsers with dynamic dispatch
#[derive(Default)]
pub struct ProtocolRegistry {
    parsers: HashMap<String, Arc<dyn ProtocolParser>>,
}

impl ProtocolRegistry {
    /// Creates a new empty registry
    pub fn new() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    /// Creates a registry with all built-in parsers registered
    pub fn with_builtin_parsers() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(ShadowsocksParser));
        registry.register(Arc::new(VMessParser));
        registry.register(Arc::new(VLessParser));
        registry.register(Arc::new(TrojanParser));
        registry.register(Arc::new(Hysteria2Parser::new("hysteria2")));
        registry.register(Arc::new(Hysteria2Parser::new("hy2")));
        registry.register(Arc::new(TuicParser));
        registry
    }

    /// Registers a protocol parser
    pub fn register(&mut self, parser: Arc<dyn ProtocolParser>) {
        self.parsers.insert(parser.scheme().to_string(), parser);
    }

    /// Gets a parser for the given scheme
    pub fn get(&self, scheme: &str) -> Option<&Arc<dyn ProtocolParser>> {
        self.parsers.get(scheme)
    }

    /// Parses a URI using the appropriate parser
    pub fn parse_uri(&self, uri: &str) -> Result<Outbound> {
        let scheme = extract_scheme(uri)?;
        debug!("Parsing URI with scheme '{}': {}", scheme, uri);

        let parser = self
            .parsers
            .get(scheme)
            .ok_or_else(|| anyhow!("No parser registered for scheme: {}", scheme))?;

        let result = parser.parse(uri);
        match &result {
            Ok(outbound) => {
                let tag = crate::transform::get_outbound_tag(outbound)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<no tag>".to_string());
                debug!("Successfully parsed {} URI -> outbound '{}'", scheme, tag);
            }
            Err(e) => {
                debug!("Failed to parse {} URI: {}", scheme, e);
            }
        }
        result
    }

    /// Parses multiple URIs from content (one per line)
    pub fn parse_uri_list(&self, content: &str) -> Vec<Result<Outbound>> {
        let lines: Vec<&str> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        debug!("Parsing {} URI lines from content", lines.len());

        lines.into_iter().map(|line| self.parse_uri(line)).collect()
    }

    /// Parses multiple URIs, collecting only successful results
    pub fn parse_uri_list_lossy(&self, content: &str) -> Vec<Outbound> {
        let results = self.parse_uri_list(content);
        let total = results.len();

        let outbounds: Vec<Outbound> = results
            .into_iter()
            .filter_map(|r| match r {
                Ok(outbound) => Some(outbound),
                Err(e) => {
                    warn!("Failed to parse URI: {}", e);
                    None
                }
            })
            .collect();

        let success = outbounds.len();
        let failed = total - success;
        debug!(
            "URI list parsing complete: {} total, {} successful, {} failed",
            total, success, failed
        );

        outbounds
    }
}

/// Extracts the scheme from a URI
fn extract_scheme(uri: &str) -> Result<&str> {
    // First check that :// actually exists in the URI
    if !uri.contains("://") {
        bail!("Invalid URI: missing scheme separator ://");
    }
    uri.split("://")
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("Invalid URI: missing scheme"))
}

// ============================================================================
// Subscription Parser Trait
// ============================================================================

/// Trait for parsing different subscription formats
pub trait SubscriptionParser: Send + Sync {
    /// Returns the subscription type this parser handles
    fn subscription_type(&self) -> SubscriptionType;

    /// Parses subscription content into a list of outbounds
    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>>;
}

/// Parser for Sing-box JSON subscriptions
pub struct SingBoxJsonParser;

impl SubscriptionParser for SingBoxJsonParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::SingBoxJson
    }

    fn parse(&self, content: &str, _registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        #[derive(Deserialize)]
        struct SingBoxSubscription {
            #[serde(default)]
            outbounds: Vec<Outbound>,
        }

        debug!("Parsing Sing-box JSON subscription");
        let subscription: SingBoxSubscription =
            serde_json::from_str(content).context("Failed to parse Sing-box JSON subscription")?;

        debug!(
            "Sing-box JSON parsing complete: {} outbounds found",
            subscription.outbounds.len()
        );
        for outbound in &subscription.outbounds {
            let tag = crate::transform::get_outbound_tag(outbound)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<no tag>".to_string());
            trace!("  - Outbound: {}", tag);
        }

        Ok(subscription.outbounds)
    }
}

/// Parser for URI list subscriptions (both plain and Base64 encoded)
pub struct UriListParser;

impl SubscriptionParser for UriListParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::PlainUriList
    }

    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        debug!("Parsing plain URI list subscription");
        let outbounds = registry.parse_uri_list_lossy(content);
        debug!(
            "Plain URI list parsing complete: {} outbounds",
            outbounds.len()
        );
        Ok(outbounds)
    }
}

/// Parser for Base64 encoded URI lists
pub struct Base64UriListParser;

impl SubscriptionParser for Base64UriListParser {
    fn subscription_type(&self) -> SubscriptionType {
        SubscriptionType::Base64UriList
    }

    fn parse(&self, content: &str, registry: &ProtocolRegistry) -> Result<Vec<Outbound>> {
        debug!("Parsing Base64 encoded URI list subscription");
        let decoded = decode_subscription_content(content)?;
        debug!("Base64 decoded content length: {} bytes", decoded.len());
        let outbounds = registry.parse_uri_list_lossy(&decoded);
        debug!(
            "Base64 URI list parsing complete: {} outbounds",
            outbounds.len()
        );
        Ok(outbounds)
    }
}

// ============================================================================
// Unified Subscription Parsing
// ============================================================================

/// Parses subscription content with automatic type detection
pub fn parse_subscription(content: &str) -> Result<Vec<Outbound>> {
    let registry = ProtocolRegistry::with_builtin_parsers();
    parse_subscription_with_registry(content, &registry)
}

/// Parses subscription content using a custom registry
pub fn parse_subscription_with_registry(
    content: &str,
    registry: &ProtocolRegistry,
) -> Result<Vec<Outbound>> {
    let subscription_type = detect_subscription_type(content);
    debug!("Detected subscription type: {}", subscription_type);

    match subscription_type {
        SubscriptionType::SingBoxJson => SingBoxJsonParser.parse(content, registry),
        SubscriptionType::PlainUriList => UriListParser.parse(content, registry),
        SubscriptionType::Base64UriList => Base64UriListParser.parse(content, registry),
        SubscriptionType::ClashYaml => {
            bail!("Clash YAML format is not yet supported")
        }
        SubscriptionType::Unknown => {
            bail!("Unable to detect subscription format")
        }
    }
}

// ============================================================================
// Shadowsocks Parser
// ============================================================================

/// Parser for Shadowsocks (ss://) URIs
///
/// Supports both SIP002 format and legacy format:
/// - SIP002: ss://BASE64(method:password)@host:port#tag
/// - SIP002 with userinfo: ss://method:password@host:port#tag
/// - Legacy: ss://BASE64(method:password@host:port)#tag
pub struct ShadowsocksParser;

impl ProtocolParser for ShadowsocksParser {
    fn scheme(&self) -> &str {
        "ss"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        let uri = uri.trim();
        trace!("Parsing Shadowsocks URI");

        // Remove the ss:// prefix
        let without_scheme = uri
            .strip_prefix("ss://")
            .ok_or_else(|| anyhow!("Invalid Shadowsocks URI: missing ss:// prefix"))?;

        // Extract fragment (tag) if present
        let (main_part, tag) = match without_scheme.rfind('#') {
            Some(pos) => {
                let tag = urlencoding::decode(&without_scheme[pos + 1..])
                    .unwrap_or_else(|_| without_scheme[pos + 1..].into())
                    .into_owned();
                (&without_scheme[..pos], Some(tag.clone()))
            }
            None => (without_scheme, None),
        };

        // Try to parse as SIP002 format first (has @ separator)
        if let Some(at_pos) = main_part.rfind('@') {
            trace!("Parsing as SIP002 format (found @ separator)");
            return self.parse_sip002(main_part, at_pos, tag);
        }

        // Try legacy format (entire content is Base64 encoded)
        trace!("Parsing as legacy Base64 format");
        self.parse_legacy(main_part, tag)
    }
}

impl ShadowsocksParser {
    /// Parses SIP002 format: BASE64(method:password)@host:port or method:password@host:port
    fn parse_sip002(
        &self,
        main_part: &str,
        at_pos: usize,
        tag: Option<String>,
    ) -> Result<Outbound> {
        let userinfo = &main_part[..at_pos];
        let hostport = &main_part[at_pos + 1..];

        // Parse host:port
        let (server, server_port) = parse_host_port(hostport)?;

        // Decode userinfo (might be Base64 or plain method:password)
        let (method, password) = self.parse_userinfo(userinfo)?;

        let final_tag = tag.unwrap_or_else(|| format!("{}:{}", server, server_port));

        Ok(Outbound::Shadowsocks(ShadowsocksOutbound {
            tag: Some(final_tag),
            server: Some(server),
            server_port: Some(server_port),
            method: Some(method),
            password: Some(password),
            plugin: None,
            plugin_opts: None,
            network: None,
            udp_over_tcp: None,
            multiplex: None,
            dial: DialFields::default(),
        }))
    }

    /// Parses legacy format: BASE64(method:password@host:port)
    fn parse_legacy(&self, main_part: &str, tag: Option<String>) -> Result<Outbound> {
        let decoded = decode_base64(main_part)
            .and_then(|b| String::from_utf8(b).context("Invalid UTF-8 in Shadowsocks URI"))
            .context("Failed to decode legacy Shadowsocks URI")?;

        // Parse decoded content: method:password@host:port
        let at_pos = decoded
            .rfind('@')
            .ok_or_else(|| anyhow!("Invalid legacy Shadowsocks format: missing @"))?;

        let userinfo = &decoded[..at_pos];
        let hostport = &decoded[at_pos + 1..];

        let (server, server_port) = parse_host_port(hostport)?;

        let colon_pos = userinfo.find(':').ok_or_else(|| {
            anyhow!("Invalid Shadowsocks userinfo: missing method:password separator")
        })?;

        let method = userinfo[..colon_pos].to_string();
        let password = userinfo[colon_pos + 1..].to_string();

        let final_tag = tag.unwrap_or_else(|| format!("{}:{}", server, server_port));

        Ok(Outbound::Shadowsocks(ShadowsocksOutbound {
            tag: Some(final_tag),
            server: Some(server),
            server_port: Some(server_port),
            method: Some(method),
            password: Some(password),
            plugin: None,
            plugin_opts: None,
            network: None,
            udp_over_tcp: None,
            multiplex: None,
            dial: DialFields::default(),
        }))
    }

    /// Parses userinfo which can be Base64(method:password) or method:password
    fn parse_userinfo(&self, userinfo: &str) -> Result<(String, String)> {
        // First try to decode as Base64
        if let Ok(decoded) = decode_base64(userinfo)
            && let Ok(decoded_str) = String::from_utf8(decoded)
            && let Some(colon_pos) = decoded_str.find(':')
        {
            let method = decoded_str[..colon_pos].to_string();
            let password = decoded_str[colon_pos + 1..].to_string();
            return Ok((method, password));
        }

        // Try as plain method:password (URL-decoded)
        let decoded_userinfo = urlencoding::decode(userinfo)
            .unwrap_or_else(|_| userinfo.into())
            .into_owned();

        let colon_pos = decoded_userinfo
            .find(':')
            .ok_or_else(|| anyhow!("Invalid Shadowsocks userinfo format"))?;

        let method = decoded_userinfo[..colon_pos].to_string();
        let password = decoded_userinfo[colon_pos + 1..].to_string();

        Ok((method, password))
    }
}

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
        let url = Url::parse(uri).context("Failed to parse VLESS URI")?;

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
        let url = Url::parse(uri).context("Failed to parse Trojan URI")?;

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

// ============================================================================
// Hysteria2 Parser
// ============================================================================

/// Parser for Hysteria2 (hysteria2:// or hy2://) URIs
///
/// Format: hysteria2://auth@host:port?params#tag
pub struct Hysteria2Parser {
    scheme: &'static str,
}

impl Hysteria2Parser {
    pub fn new(scheme: &'static str) -> Self {
        Self { scheme }
    }
}

impl ProtocolParser for Hysteria2Parser {
    fn scheme(&self) -> &str {
        self.scheme
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing Hysteria2 URI (scheme: {})", self.scheme);
        let url = Url::parse(uri).context("Failed to parse Hysteria2 URI")?;

        let password = urlencoding::decode(url.username())
            .unwrap_or_else(|_| url.username().into())
            .into_owned();

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("Hysteria2 URI missing host"))?
            .to_string();

        let server_port = url
            .port()
            .ok_or_else(|| anyhow!("Hysteria2 URI missing port"))?;

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
        let tls = Some(OutboundTlsConfig {
            enabled: true,
            server_name: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            insecure: params
                .get("insecure")
                .map(|s| s == "1" || s == "true")
                .unwrap_or(false),
            ..Default::default()
        });

        // Build obfs config
        let obfs = params.get("obfs").and_then(|obfs_type| {
            if obfs_type.is_empty() || obfs_type == "none" {
                None
            } else {
                Some(Hysteria2Obfs {
                    obfs_type: Some(obfs_type.clone()),
                    password: params.get("obfs-password").cloned(),
                })
            }
        });

        Ok(Outbound::Hysteria2(Hysteria2Outbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            server_ports: Vec::new(),
            hop_interval: None,
            up_mbps: params.get("up").and_then(|s| s.parse().ok()),
            down_mbps: params.get("down").and_then(|s| s.parse().ok()),
            obfs,
            password: if password.is_empty() {
                None
            } else {
                Some(password)
            },
            network: None,
            tls,
            brutal_debug: false,
            dial: DialFields::default(),
        }))
    }
}

// ============================================================================
// TUIC Parser
// ============================================================================

/// Parser for TUIC (tuic://) URIs
///
/// Format: tuic://uuid:password@host:port?params#tag
pub struct TuicParser;

impl ProtocolParser for TuicParser {
    fn scheme(&self) -> &str {
        "tuic"
    }

    fn parse(&self, uri: &str) -> Result<Outbound> {
        trace!("Parsing TUIC URI");
        let url = Url::parse(uri).context("Failed to parse TUIC URI")?;

        let uuid = url.username().to_string();
        if uuid.is_empty() {
            bail!("TUIC URI missing UUID");
        }

        let password = url.password().map(|p| {
            urlencoding::decode(p)
                .unwrap_or_else(|_| p.into())
                .into_owned()
        });

        let server = url
            .host_str()
            .ok_or_else(|| anyhow!("TUIC URI missing host"))?
            .to_string();

        let server_port = url.port().ok_or_else(|| anyhow!("TUIC URI missing port"))?;

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
        let tls = Some(OutboundTlsConfig {
            enabled: true,
            server_name: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default(),
            ..Default::default()
        });

        Ok(Outbound::Tuic(TuicOutbound {
            tag: Some(tag),
            server: Some(server),
            server_port: Some(server_port),
            uuid: Some(uuid),
            password,
            congestion_control: params.get("congestion_control").cloned(),
            udp_relay_mode: params.get("udp_relay_mode").cloned(),
            udp_over_stream: params
                .get("udp_over_stream")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            zero_rtt_handshake: params
                .get("zero_rtt_handshake")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false),
            heartbeat: params.get("heartbeat").cloned(),
            network: None,
            tls,
            dial: DialFields::default(),
        }))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parses host:port string, handling IPv6 addresses in brackets
fn parse_host_port(hostport: &str) -> Result<(String, u16)> {
    // Handle IPv6 addresses: [::1]:8080
    if hostport.starts_with('[') {
        let bracket_end = hostport
            .find(']')
            .ok_or_else(|| anyhow!("Invalid IPv6 address: missing closing bracket"))?;

        let host = hostport[1..bracket_end].to_string();
        let port_str = hostport
            .get(bracket_end + 2..)
            .ok_or_else(|| anyhow!("Missing port after IPv6 address"))?;

        let port: u16 = port_str.parse().context("Invalid port number")?;
        return Ok((host, port));
    }

    // Handle regular host:port
    let colon_pos = hostport
        .rfind(':')
        .ok_or_else(|| anyhow!("Invalid host:port format: missing colon"))?;

    let host = hostport[..colon_pos].to_string();
    let port: u16 = hostport[colon_pos + 1..]
        .parse()
        .context("Invalid port number")?;

    Ok((host, port))
}

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Subscription Type Detection Tests
    // ========================================================================

    #[test]
    fn test_detect_singbox_json() {
        let content = r#"{"outbounds": [{"type": "direct", "tag": "direct"}]}"#;
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::SingBoxJson
        );
    }

    #[test]
    fn test_detect_singbox_json_with_whitespace() {
        let content = r#"
        {
            "outbounds": []
        }
        "#;
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::SingBoxJson
        );
    }

    #[test]
    fn test_detect_plain_uri_list() {
        let content = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server:8388#name\nvmess://xxx";
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::PlainUriList
        );
    }

    #[test]
    fn test_detect_base64_uri_list() {
        // Base64 encoded: "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server:8388#name"
        let content = "c3M6Ly9ZV1Z6TFRFeU9DMW5ZMjA2Y0dGemMzZHZjbVFAc2VydmVyOjgzODgjbmFtZQ==";
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::Base64UriList
        );
    }

    #[test]
    fn test_detect_clash_yaml() {
        let content = "proxies:\n  - name: test\n    type: ss";
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::ClashYaml
        );
    }

    // ========================================================================
    // Base64 Decoding Tests
    // ========================================================================

    #[test]
    fn test_decode_base64_standard() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_decode_base64_url_safe() {
        let encoded = "SGVsbG8tV29ybGRf";
        let result = decode_base64(encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_base64_with_linebreaks() {
        let encoded = "SGVs\nbG8g\nV29y\nbGQ=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_decode_base64_without_padding() {
        let encoded = "SGVsbG8gV29ybGQ";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    // ========================================================================
    // Shadowsocks Parser Tests
    // ========================================================================

    #[test]
    fn test_shadowsocks_sip002_base64_userinfo() {
        let uri = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server.example.com:8388#My%20Server";
        let parser = ShadowsocksParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.server, Some("server.example.com".to_string()));
            assert_eq!(ss.server_port, Some(8388));
            assert_eq!(ss.method, Some("aes-128-gcm".to_string()));
            assert_eq!(ss.password, Some("password".to_string()));
            assert_eq!(ss.tag, Some("My Server".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_legacy_format() {
        // Base64 of "aes-128-gcm:password@server.example.com:8388"
        let uri = "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAc2VydmVyLmV4YW1wbGUuY29tOjgzODg#Test";
        let parser = ShadowsocksParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.server, Some("server.example.com".to_string()));
            assert_eq!(ss.server_port, Some(8388));
            assert_eq!(ss.method, Some("aes-128-gcm".to_string()));
            assert_eq!(ss.password, Some("password".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    #[test]
    fn test_shadowsocks_without_tag() {
        let uri = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:443";
        let parser = ShadowsocksParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Shadowsocks(ss) = outbound {
            assert_eq!(ss.tag, Some("example.com:443".to_string()));
        } else {
            panic!("Expected Shadowsocks outbound");
        }
    }

    // ========================================================================
    // VMess Parser Tests
    // ========================================================================

    #[test]
    fn test_vmess_basic() {
        let json = r#"{"v":"2","ps":"Test Server","add":"server.com","port":443,"id":"uuid-here","aid":0,"scy":"auto","net":"tcp","tls":""}"#;
        let encoded = STANDARD.encode(json);
        let uri = format!("vmess://{}", encoded);

        let parser = VMessParser;
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert_eq!(vmess.server, Some("server.com".to_string()));
            assert_eq!(vmess.server_port, Some(443));
            assert_eq!(vmess.uuid, Some("uuid-here".to_string()));
            assert_eq!(vmess.tag, Some("Test Server".to_string()));
        } else {
            panic!("Expected VMess outbound");
        }
    }

    #[test]
    fn test_vmess_with_websocket() {
        let json = r#"{"v":"2","ps":"WS Server","add":"server.com","port":443,"id":"uuid","aid":0,"net":"ws","tls":"tls","sni":"sni.com","path":"/ws","host":"host.com"}"#;
        let encoded = STANDARD.encode(json);
        let uri = format!("vmess://{}", encoded);

        let parser = VMessParser;
        let outbound = parser.parse(&uri).unwrap();

        if let Outbound::VMess(vmess) = outbound {
            assert!(vmess.tls.is_some());
            assert!(vmess.transport.is_some());
            if let Some(V2RayTransport::WebSocket(ws)) = vmess.transport {
                assert_eq!(ws.path, Some("/ws".to_string()));
            } else {
                panic!("Expected WebSocket transport");
            }
        } else {
            panic!("Expected VMess outbound");
        }
    }

    // ========================================================================
    // VLESS Parser Tests
    // ========================================================================

    #[test]
    fn test_vless_basic() {
        let uri = "vless://uuid@server.com:443?security=tls&sni=sni.com#Test";
        let parser = VLessParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert_eq!(vless.server, Some("server.com".to_string()));
            assert_eq!(vless.server_port, Some(443));
            assert_eq!(vless.uuid, Some("uuid".to_string()));
            assert_eq!(vless.tag, Some("Test".to_string()));
            assert!(vless.tls.is_some());
        } else {
            panic!("Expected VLESS outbound");
        }
    }

    #[test]
    fn test_vless_with_reality() {
        let uri = "vless://uuid@server.com:443?security=reality&sni=sni.com&pbk=publickey&sid=shortid&fp=chrome#Reality";
        let parser = VLessParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::VLess(vless) = outbound {
            assert!(vless.tls.is_some());
            let tls = vless.tls.unwrap();
            assert!(tls.reality.is_some());
            let reality = tls.reality.unwrap();
            assert_eq!(reality.public_key, Some("publickey".to_string()));
            assert_eq!(reality.short_id, Some("shortid".to_string()));
        } else {
            panic!("Expected VLESS outbound");
        }
    }

    // ========================================================================
    // Trojan Parser Tests
    // ========================================================================

    #[test]
    fn test_trojan_basic() {
        let uri = "trojan://password123@server.com:443?sni=sni.com#Trojan%20Server";
        let parser = TrojanParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Trojan(trojan) = outbound {
            assert_eq!(trojan.server, Some("server.com".to_string()));
            assert_eq!(trojan.server_port, Some(443));
            assert_eq!(trojan.password, Some("password123".to_string()));
            assert_eq!(trojan.tag, Some("Trojan Server".to_string()));
            assert!(trojan.tls.is_some());
        } else {
            panic!("Expected Trojan outbound");
        }
    }

    // ========================================================================
    // Hysteria2 Parser Tests
    // ========================================================================

    #[test]
    fn test_hysteria2_basic() {
        let uri = "hysteria2://password@server.com:443?sni=sni.com#Hy2";
        let parser = Hysteria2Parser::new("hysteria2");
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.server, Some("server.com".to_string()));
            assert_eq!(hy2.server_port, Some(443));
            assert_eq!(hy2.password, Some("password".to_string()));
            assert_eq!(hy2.tag, Some("Hy2".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    #[test]
    fn test_hy2_scheme() {
        let uri = "hy2://password@server.com:443#Short";
        let parser = Hysteria2Parser::new("hy2");
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Hysteria2(hy2) = outbound {
            assert_eq!(hy2.server, Some("server.com".to_string()));
        } else {
            panic!("Expected Hysteria2 outbound");
        }
    }

    // ========================================================================
    // TUIC Parser Tests
    // ========================================================================

    #[test]
    fn test_tuic_basic() {
        let uri = "tuic://uuid:password@server.com:443?sni=sni.com&congestion_control=bbr#TUIC";
        let parser = TuicParser;
        let outbound = parser.parse(uri).unwrap();

        if let Outbound::Tuic(tuic) = outbound {
            assert_eq!(tuic.server, Some("server.com".to_string()));
            assert_eq!(tuic.server_port, Some(443));
            assert_eq!(tuic.uuid, Some("uuid".to_string()));
            assert_eq!(tuic.password, Some("password".to_string()));
            assert_eq!(tuic.congestion_control, Some("bbr".to_string()));
        } else {
            panic!("Expected TUIC outbound");
        }
    }

    // ========================================================================
    // Protocol Registry Tests
    // ========================================================================

    #[test]
    fn test_registry_with_builtin_parsers() {
        let registry = ProtocolRegistry::with_builtin_parsers();

        assert!(registry.get("ss").is_some());
        assert!(registry.get("vmess").is_some());
        assert!(registry.get("vless").is_some());
        assert!(registry.get("trojan").is_some());
        assert!(registry.get("hysteria2").is_some());
        assert!(registry.get("hy2").is_some());
        assert!(registry.get("tuic").is_some());
    }

    #[test]
    fn test_registry_parse_uri_list() {
        let content = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server1.com:8388#Server1\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server2.com:8389#Server2";
        let registry = ProtocolRegistry::with_builtin_parsers();

        let outbounds = registry.parse_uri_list_lossy(content);
        assert_eq!(outbounds.len(), 2);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_parse_subscription_singbox_json() {
        let content = r#"{"outbounds": [{"type": "direct", "tag": "direct-out"}]}"#;
        let outbounds = parse_subscription(content).unwrap();
        assert_eq!(outbounds.len(), 1);
    }

    #[test]
    fn test_parse_subscription_plain_uri_list() {
        let content = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server.com:8388#Test";
        let outbounds = parse_subscription(content).unwrap();
        assert_eq!(outbounds.len(), 1);
    }

    #[test]
    fn test_parse_subscription_base64_uri_list() {
        // Base64 encoded single SS URI
        let plain = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@server.com:8388#Test";
        let encoded = STANDARD.encode(plain);

        let outbounds = parse_subscription(&encoded).unwrap();
        assert_eq!(outbounds.len(), 1);
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_parse_host_port_ipv4() {
        let (host, port) = parse_host_port("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_extract_scheme() {
        assert_eq!(extract_scheme("ss://example").unwrap(), "ss");
        assert_eq!(extract_scheme("vmess://example").unwrap(), "vmess");
        assert!(extract_scheme("invalid").is_err());
    }
}

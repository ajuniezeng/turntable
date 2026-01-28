//! Route configuration types for sing-box.
//!
//! This module contains typed configuration for routing rules, rule sets,
//! and route actions.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

use crate::config::serde_helpers::{is_false, is_zero_i32, is_zero_u16, string_or_vec, u16_or_vec};
use crate::config::shared::{DomainResolver, DomainStrategy, NetworkType};

// ============================================================================
// Route Configuration
// ============================================================================

/// Main route configuration.
///
/// Controls how connections are routed to outbounds based on matching rules.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Route {
    /// List of route rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,

    /// List of rule sets (since 1.8.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<RuleSet>,

    /// Default outbound tag (first outbound used if empty)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "final")]
    pub final_outbound: Option<String>,

    /// Bind outbound connections to default NIC (Linux/Windows/macOS)
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_detect_interface: bool,

    /// Accept Android VPN as upstream NIC when auto_detect_interface enabled (Android only)
    #[serde(default, skip_serializing_if = "is_false")]
    pub override_android_vpn: bool,

    /// Bind outbound connections to specified NIC (Linux/Windows/macOS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,

    /// Default routing mark (Linux only)
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub default_mark: i32,

    /// Default domain resolver (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolver>,

    /// Default network strategy (since 1.11.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_strategy: Option<NetworkStrategy>,

    /// Default network types (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_network_type: Vec<NetworkType>,

    /// Default fallback network types (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_fallback_network_type: Vec<NetworkType>,

    /// Default fallback delay (since 1.11.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_fallback_delay: Option<String>,

    // Deprecated fields (removed in 1.12.0)
    /// GeoIP database configuration (deprecated in 1.8.0, removed in 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<GeoResource>,

    /// Geosite database configuration (deprecated in 1.8.0, removed in 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite: Option<GeoResource>,
}

/// Network strategy options for routing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStrategy {
    Default,
    Hybrid,
    Fallback,
}

/// GeoIP/Geosite resource configuration (deprecated).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct GeoResource {
    /// Path to the database file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Download URL of the database
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,

    /// Outbound tag for downloading
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
}

impl Route {
    /// Create a new empty route configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route rule.
    pub fn add_rule(mut self, rule: RouteRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Add a rule set.
    pub fn add_rule_set(mut self, rule_set: RuleSet) -> Self {
        self.rule_set.push(rule_set);
        self
    }

    /// Set the final/default outbound.
    pub fn with_final(mut self, outbound: impl Into<String>) -> Self {
        self.final_outbound = Some(outbound.into());
        self
    }

    /// Enable auto interface detection.
    pub fn with_auto_detect_interface(mut self) -> Self {
        self.auto_detect_interface = true;
        self
    }

    /// Set the default interface.
    pub fn with_default_interface(mut self, interface: impl Into<String>) -> Self {
        self.default_interface = Some(interface.into());
        self
    }

    /// Set the default mark.
    pub fn with_default_mark(mut self, mark: i32) -> Self {
        self.default_mark = mark;
        self
    }
}

// ============================================================================
// Route Rules
// ============================================================================

/// A route rule that matches connections and specifies an action.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RouteRule {
    /// Rule type (omit for default, "logical" for logical rules)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub rule_type: Option<String>,

    /// Logical mode ("and" or "or") for logical rules
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,

    /// Nested rules for logical rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRule>,

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

    /// Match network type (tcp, udp, icmp since 1.13.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub network: Vec<String>,

    /// Match authenticated username
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

    /// Match sniffed client type (since 1.10.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub client: Vec<String>,

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

    /// Match geosite (deprecated in 1.8.0, removed in 1.12.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub geosite: Vec<String>,

    /// Match source geoip (deprecated in 1.8.0, removed in 1.12.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_geoip: Vec<String>,

    /// Match geoip (deprecated in 1.8.0, removed in 1.12.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub geoip: Vec<String>,

    /// Match source IP CIDR
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_ip_cidr: Vec<String>,

    /// Match non-public source IP (since 1.8.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_ip_is_private: bool,

    /// Match IP CIDR
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub ip_cidr: Vec<String>,

    /// Match non-public IP (since 1.8.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub ip_is_private: bool,

    /// Match source port
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "u16_or_vec"
    )]
    pub source_port: Vec<u16>,

    /// Match source port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_port_range: Vec<String>,

    /// Match port
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "u16_or_vec"
    )]
    pub port: Vec<u16>,

    /// Match port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub port_range: Vec<String>,

    /// Match process name (Linux/Windows/macOS)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_name: Vec<String>,

    /// Match process path (Linux/Windows/macOS)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_path: Vec<String>,

    /// Match process path regex (since 1.10.0, Linux/Windows/macOS)
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
    pub user_id: Vec<i32>,

    /// Match Clash mode
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,

    /// Match network type (since 1.11.0, Android/Apple)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<NetworkType>,

    /// Match expensive network (since 1.11.0, Android/Apple)
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_expensive: bool,

    /// Match constrained network (since 1.11.0, Apple)
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_constrained: bool,

    /// Match interface address (since 1.13.0)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub interface_address: HashMap<String, Vec<String>>,

    /// Match network interface address (since 1.13.0)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub network_interface_address: HashMap<String, Vec<String>>,

    /// Match default interface address (since 1.13.0)
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

    /// Match preferred routes by outbound tags (since 1.13.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub preferred_by: Vec<String>,

    /// Match rule sets (since 1.8.0)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub rule_set: Vec<String>,

    /// Make ip_cidr in rule-sets match source IP (deprecated in 1.10.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ipcidr_match_source: bool,

    /// Make ip_cidr in rule-sets match source IP (since 1.10.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub rule_set_ip_cidr_match_source: bool,

    /// Invert match result
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,

    // Action fields
    /// Rule action (since 1.11.0)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_option_rule_action"
    )]
    pub action: Option<RuleAction>,

    /// Target outbound tag (deprecated in 1.11.0, moved to action)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
}

/// Logical mode for combining rules.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogicalMode {
    And,
    Or,
}

impl RouteRule {
    /// Create a new empty rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a logical rule.
    pub fn logical(mode: LogicalMode, rules: Vec<RouteRule>) -> Self {
        Self {
            rule_type: Some("logical".to_string()),
            mode: Some(mode),
            rules,
            ..Default::default()
        }
    }

    /// Set the action.
    pub fn with_action(mut self, action: RuleAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the outbound (deprecated, use action instead).
    pub fn with_outbound(mut self, outbound: impl Into<String>) -> Self {
        self.outbound = Some(outbound.into());
        self
    }

    /// Match inbound tags.
    pub fn match_inbound(mut self, inbounds: Vec<String>) -> Self {
        self.inbound = inbounds;
        self
    }

    /// Match domains.
    pub fn match_domain(mut self, domains: Vec<String>) -> Self {
        self.domain = domains;
        self
    }

    /// Match domain suffixes.
    pub fn match_domain_suffix(mut self, suffixes: Vec<String>) -> Self {
        self.domain_suffix = suffixes;
        self
    }

    /// Match domain keywords.
    pub fn match_domain_keyword(mut self, keywords: Vec<String>) -> Self {
        self.domain_keyword = keywords;
        self
    }

    /// Match IP CIDRs.
    pub fn match_ip_cidr(mut self, cidrs: Vec<String>) -> Self {
        self.ip_cidr = cidrs;
        self
    }

    /// Match source IP CIDRs.
    pub fn match_source_ip_cidr(mut self, cidrs: Vec<String>) -> Self {
        self.source_ip_cidr = cidrs;
        self
    }

    /// Match ports.
    pub fn match_port(mut self, ports: Vec<u16>) -> Self {
        self.port = ports;
        self
    }

    /// Match protocols.
    pub fn match_protocol(mut self, protocols: Vec<String>) -> Self {
        self.protocol = protocols;
        self
    }

    /// Match process names.
    pub fn match_process_name(mut self, names: Vec<String>) -> Self {
        self.process_name = names;
        self
    }

    /// Match rule sets.
    pub fn match_rule_set(mut self, rule_sets: Vec<String>) -> Self {
        self.rule_set = rule_sets;
        self
    }

    /// Match geosite (deprecated in 1.8.0, removed in 1.12.0).
    pub fn match_geosite(mut self, geosites: Vec<String>) -> Self {
        self.geosite = geosites;
        self
    }

    /// Match geoip (deprecated in 1.8.0, removed in 1.12.0).
    pub fn match_geoip(mut self, geoips: Vec<String>) -> Self {
        self.geoip = geoips;
        self
    }

    /// Match source geoip (deprecated in 1.8.0, removed in 1.12.0).
    pub fn match_source_geoip(mut self, geoips: Vec<String>) -> Self {
        self.source_geoip = geoips;
        self
    }

    /// Invert the match result.
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }
}

// ============================================================================
// Rule Actions
// ============================================================================

/// Rule action types.
///
/// Supports both simple string format (e.g., `"action": "sniff"`) and
/// object format (e.g., `"action": {"action": "sniff", "timeout": "500ms"}`).
#[derive(Clone, Debug)]
pub enum RuleAction {
    /// Route to an outbound
    Route(RouteAction),
    /// Bypass at kernel level (since 1.13.0)
    Bypass(BypassAction),
    /// Reject the connection
    Reject(RejectAction),
    /// Hijack DNS requests
    HijackDns,
    /// Set route options
    RouteOptions(RouteOptionsAction),
    /// Perform protocol sniffing
    Sniff(SniffAction),
    /// Resolve domain to IP
    Resolve(ResolveAction),
}

impl Serialize for RuleAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Check if we can use the simple string format (when inner struct is default)
        match self {
            RuleAction::Sniff(action) if *action == SniffAction::default() => {
                serializer.serialize_str("sniff")
            }
            RuleAction::HijackDns => serializer.serialize_str("hijack-dns"),
            RuleAction::Reject(action) if *action == RejectAction::default() => {
                serializer.serialize_str("reject")
            }
            RuleAction::Route(action) if *action == RouteAction::default() => {
                serializer.serialize_str("route")
            }
            RuleAction::Bypass(action) if *action == BypassAction::default() => {
                serializer.serialize_str("bypass")
            }
            RuleAction::RouteOptions(action) if *action == RouteOptionsAction::default() => {
                serializer.serialize_str("route-options")
            }
            RuleAction::Resolve(action) if *action == ResolveAction::default() => {
                serializer.serialize_str("resolve")
            }
            // For non-default cases, use the tagged object format
            _ => {
                #[derive(Serialize)]
                #[serde(tag = "action", rename_all = "kebab-case")]
                enum RuleActionTagged<'a> {
                    Route(&'a RouteAction),
                    Bypass(&'a BypassAction),
                    Reject(&'a RejectAction),
                    HijackDns,
                    RouteOptions(&'a RouteOptionsAction),
                    Sniff(&'a SniffAction),
                    Resolve(&'a ResolveAction),
                }

                let tagged = match self {
                    RuleAction::Route(a) => RuleActionTagged::Route(a),
                    RuleAction::Bypass(a) => RuleActionTagged::Bypass(a),
                    RuleAction::Reject(a) => RuleActionTagged::Reject(a),
                    RuleAction::HijackDns => RuleActionTagged::HijackDns,
                    RuleAction::RouteOptions(a) => RuleActionTagged::RouteOptions(a),
                    RuleAction::Sniff(a) => RuleActionTagged::Sniff(a),
                    RuleAction::Resolve(a) => RuleActionTagged::Resolve(a),
                };
                tagged.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for RuleAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let value = serde_json::Value::deserialize(deserializer)?;

        match value {
            // Handle string format: "sniff", "hijack-dns", "reject"
            serde_json::Value::String(s) => match s.as_str() {
                "sniff" => Ok(RuleAction::Sniff(SniffAction::default())),
                "hijack-dns" => Ok(RuleAction::HijackDns),
                "reject" => Ok(RuleAction::Reject(RejectAction::default())),
                "route" => Ok(RuleAction::Route(RouteAction::default())),
                "bypass" => Ok(RuleAction::Bypass(BypassAction::default())),
                "route-options" => Ok(RuleAction::RouteOptions(RouteOptionsAction::default())),
                "resolve" => Ok(RuleAction::Resolve(ResolveAction::default())),
                other => Err(D::Error::custom(format!("unknown action: {}", other))),
            },
            // Handle object format: {"action": "sniff", ...}
            serde_json::Value::Object(_) => {
                #[derive(Deserialize)]
                #[serde(tag = "action", rename_all = "kebab-case")]
                enum RuleActionInner {
                    Route(RouteAction),
                    Bypass(BypassAction),
                    Reject(RejectAction),
                    HijackDns,
                    RouteOptions(RouteOptionsAction),
                    Sniff(SniffAction),
                    Resolve(ResolveAction),
                }

                let inner: RuleActionInner =
                    serde_json::from_value(value).map_err(D::Error::custom)?;
                Ok(match inner {
                    RuleActionInner::Route(a) => RuleAction::Route(a),
                    RuleActionInner::Bypass(a) => RuleAction::Bypass(a),
                    RuleActionInner::Reject(a) => RuleAction::Reject(a),
                    RuleActionInner::HijackDns => RuleAction::HijackDns,
                    RuleActionInner::RouteOptions(a) => RuleAction::RouteOptions(a),
                    RuleActionInner::Sniff(a) => RuleAction::Sniff(a),
                    RuleActionInner::Resolve(a) => RuleAction::Resolve(a),
                })
            }
            _ => Err(D::Error::custom("expected string or object for action")),
        }
    }
}

/// Deserialize Option<RuleAction> handling both string and object formats.
fn deserialize_option_rule_action<'de, D>(deserializer: D) -> Result<Option<RuleAction>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<RuleAction>::deserialize(deserializer)
}

/// Route action - routes connection to specified outbound.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteAction {
    /// Target outbound tag (required)
    pub outbound: String,

    // Route options fields
    /// Override connection destination address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    /// Override connection destination port
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub override_port: u16,

    /// Network strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,

    /// Fallback delay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay: Option<String>,

    /// Disable domain unmapping for UDP
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_disable_domain_unmapping: bool,

    /// Connect UDP instead of listen
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_connect: bool,

    /// UDP connection timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// Fragment TLS handshakes (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_fragment: bool,

    /// TLS fragment fallback delay (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fragment_fallback_delay: Option<String>,

    /// Fragment TLS into multiple records (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_record_fragment: Option<String>,
}

impl RouteAction {
    /// Create a new route action.
    pub fn new(outbound: impl Into<String>) -> Self {
        Self {
            outbound: outbound.into(),
            ..Default::default()
        }
    }

    /// Override the destination address.
    pub fn with_override_address(mut self, address: impl Into<String>) -> Self {
        self.override_address = Some(address.into());
        self
    }

    /// Override the destination port.
    pub fn with_override_port(mut self, port: u16) -> Self {
        self.override_port = port;
        self
    }
}

/// Bypass action - bypasses sing-box at kernel level (since 1.13.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct BypassAction {
    /// Target outbound tag (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,

    // Route options fields (same as RouteAction)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub override_port: u16,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay: Option<String>,

    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_disable_domain_unmapping: bool,

    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_connect: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_fragment: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fragment_fallback_delay: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_record_fragment: Option<String>,
}

/// Reject action - rejects connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RejectAction {
    /// Reject method (default, drop, or reply for ICMP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<RejectMethod>,

    /// Don't auto-drop after many triggers
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_drop: bool,
}

/// Reject methods.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RejectMethod {
    Default,
    Drop,
    Reply,
}

impl RejectAction {
    /// Create a new reject action with default method.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a reject action with drop method.
    pub fn drop() -> Self {
        Self {
            method: Some(RejectMethod::Drop),
            ..Default::default()
        }
    }

    /// Set the reject method.
    pub fn with_method(mut self, method: RejectMethod) -> Self {
        self.method = Some(method);
        self
    }
}

/// Route options action - sets routing options without changing destination.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RouteOptionsAction {
    /// Override connection destination address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    /// Override connection destination port
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub override_port: u16,

    /// Network strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<NetworkStrategy>,

    /// Network types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<NetworkType>,

    /// Fallback network types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_network_type: Vec<NetworkType>,

    /// Fallback delay
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay: Option<String>,

    /// Disable domain unmapping for UDP
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_disable_domain_unmapping: bool,

    /// Connect UDP instead of listen
    #[serde(default, skip_serializing_if = "is_false")]
    pub udp_connect: bool,

    /// UDP connection timeout
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<String>,

    /// Fragment TLS handshakes (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub tls_fragment: bool,

    /// TLS fragment fallback delay (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fragment_fallback_delay: Option<String>,

    /// Fragment TLS into multiple records (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_record_fragment: Option<String>,
}

/// Sniff action - performs protocol sniffing.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SniffAction {
    /// Enabled sniffers (all by default)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sniffer: Vec<String>,

    /// Sniffing timeout (default: 300ms)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
}

impl SniffAction {
    /// Create a new sniff action with all sniffers enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable specific sniffers.
    pub fn with_sniffers(mut self, sniffers: Vec<String>) -> Self {
        self.sniffer = sniffers;
        self
    }

    /// Set the sniffing timeout.
    pub fn with_timeout(mut self, timeout: impl Into<String>) -> Self {
        self.timeout = Some(timeout.into());
        self
    }
}

/// Resolve action - resolves domain to IP addresses.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ResolveAction {
    /// DNS server tag to use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// DNS resolution strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,

    /// Disable cache for this query (since 1.12.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_cache: bool,

    /// Rewrite TTL in responses (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,

    /// EDNS client subnet (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

impl ResolveAction {
    /// Create a new resolve action.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use a specific DNS server.
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    /// Set the resolution strategy.
    pub fn with_strategy(mut self, strategy: DomainStrategy) -> Self {
        self.strategy = Some(strategy);
        self
    }
}

// ============================================================================
// Rule Sets
// ============================================================================

/// Rule set configuration.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleSet {
    /// Inline rule set (since 1.10.0)
    Inline(InlineRuleSet),
    /// Local file rule set
    Local(LocalRuleSet),
    /// Remote rule set
    Remote(RemoteRuleSet),
}

/// Inline rule set (since 1.10.0).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InlineRuleSet {
    /// Tag of the rule set (required)
    pub tag: String,

    /// List of headless rules (required)
    pub rules: Vec<HeadlessRule>,
}

impl InlineRuleSet {
    /// Create a new inline rule set.
    pub fn new(tag: impl Into<String>, rules: Vec<HeadlessRule>) -> Self {
        Self {
            tag: tag.into(),
            rules,
        }
    }
}

/// Local file rule set.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct LocalRuleSet {
    /// Tag of the rule set (required)
    pub tag: String,

    /// Format of the rule set file (source or binary)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleSetFormat>,

    /// File path of the rule set (required)
    pub path: String,
}

impl LocalRuleSet {
    /// Create a new local rule set.
    pub fn new(tag: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            path: path.into(),
            format: None,
        }
    }

    /// Set the format.
    pub fn with_format(mut self, format: RuleSetFormat) -> Self {
        self.format = Some(format);
        self
    }
}

/// Remote rule set.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RemoteRuleSet {
    /// Tag of the rule set (required)
    pub tag: String,

    /// Format of the rule set file (source or binary)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleSetFormat>,

    /// Download URL of the rule set (required)
    pub url: String,

    /// Outbound tag for downloading
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,

    /// Update interval (default: 1d)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<String>,
}

impl RemoteRuleSet {
    /// Create a new remote rule set.
    pub fn new(tag: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            url: url.into(),
            format: None,
            download_detour: None,
            update_interval: None,
        }
    }

    /// Set the format.
    pub fn with_format(mut self, format: RuleSetFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Set the download detour.
    pub fn with_download_detour(mut self, detour: impl Into<String>) -> Self {
        self.download_detour = Some(detour.into());
        self
    }

    /// Set the update interval.
    pub fn with_update_interval(mut self, interval: impl Into<String>) -> Self {
        self.update_interval = Some(interval.into());
        self
    }
}

/// Rule set file format.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    Source,
    Binary,
}

// ============================================================================
// Headless Rules (for rule sets)
// ============================================================================

/// Headless rule for rule sets (no action, just matching conditions).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct HeadlessRule {
    /// Rule type (omit for default, "logical" for logical rules)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub rule_type: Option<String>,

    /// Logical mode ("and" or "or") for logical rules
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,

    /// Nested rules for logical rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,

    // Match conditions (subset of RouteRule conditions)
    /// DNS query type (integers or type name strings)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,

    /// Match network type (tcp, udp)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub network: Vec<String>,

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

    /// Match IP CIDR
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub ip_cidr: Vec<String>,

    /// Match source port
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "u16_or_vec"
    )]
    pub source_port: Vec<u16>,

    /// Match source port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub source_port_range: Vec<String>,

    /// Match port
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "u16_or_vec"
    )]
    pub port: Vec<u16>,

    /// Match port range
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub port_range: Vec<String>,

    /// Match process name (Linux/Windows/macOS)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_name: Vec<String>,

    /// Match process path (Linux/Windows/macOS)
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "string_or_vec"
    )]
    pub process_path: Vec<String>,

    /// Match process path regex (since 1.10.0)
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

    /// Match network type (since 1.11.0, Android/Apple)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<NetworkType>,

    /// Match expensive network (since 1.11.0, Android/Apple)
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_expensive: bool,

    /// Match constrained network (since 1.11.0, Apple)
    #[serde(default, skip_serializing_if = "is_false")]
    pub network_is_constrained: bool,

    /// Match network interface address (since 1.13.0)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub network_interface_address: HashMap<String, Vec<String>>,

    /// Match default interface address (since 1.13.0)
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

    /// Invert match result
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
}

impl HeadlessRule {
    /// Create a new empty headless rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a logical headless rule.
    pub fn logical(mode: LogicalMode, rules: Vec<HeadlessRule>) -> Self {
        Self {
            rule_type: Some("logical".to_string()),
            mode: Some(mode),
            rules,
            ..Default::default()
        }
    }

    /// Match domains.
    pub fn match_domain(mut self, domains: Vec<String>) -> Self {
        self.domain = domains;
        self
    }

    /// Match domain suffixes.
    pub fn match_domain_suffix(mut self, suffixes: Vec<String>) -> Self {
        self.domain_suffix = suffixes;
        self
    }

    /// Match IP CIDRs.
    pub fn match_ip_cidr(mut self, cidrs: Vec<String>) -> Self {
        self.ip_cidr = cidrs;
        self
    }

    /// Invert the match result.
    pub fn invert(mut self) -> Self {
        self.invert = true;
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
    fn test_route_default_serializes_empty() {
        let route = Route::default();
        let json = serde_json::to_string(&route).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_route_with_final() {
        let route = Route::new().with_final("direct");
        let json = serde_json::to_string(&route).unwrap();
        assert!(json.contains(r#""final":"direct""#));
    }

    #[test]
    fn test_route_with_auto_detect() {
        let route = Route::new().with_auto_detect_interface();
        let json = serde_json::to_string(&route).unwrap();
        assert!(json.contains(r#""auto_detect_interface":true"#));
    }

    #[test]
    fn test_route_rule_basic() {
        let rule = RouteRule::new()
            .match_domain(vec!["example.com".to_string()])
            .with_outbound("direct");
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains(r#""domain":["example.com"]"#));
        assert!(json.contains(r#""outbound":"direct""#));
    }

    #[test]
    fn test_route_rule_with_action() {
        let rule = RouteRule::new()
            .match_port(vec![80, 443])
            .with_action(RuleAction::Route(RouteAction::new("proxy")));
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains(r#""port":[80,443]"#));
        assert!(json.contains(r#""action":"route""#));
        assert!(json.contains(r#""outbound":"proxy""#));
    }

    #[test]
    fn test_logical_rule() {
        let rule1 = RouteRule::new().match_domain(vec!["a.com".to_string()]);
        let rule2 = RouteRule::new().match_domain(vec!["b.com".to_string()]);
        let logical = RouteRule::logical(LogicalMode::Or, vec![rule1, rule2])
            .with_action(RuleAction::Route(RouteAction::new("direct")));
        let json = serde_json::to_string(&logical).unwrap();
        assert!(json.contains(r#""type":"logical""#));
        assert!(json.contains(r#""mode":"or""#));
    }

    #[test]
    fn test_reject_action() {
        let action = RuleAction::Reject(RejectAction::drop());
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"reject""#));
        assert!(json.contains(r#""method":"drop""#));
    }

    #[test]
    fn test_rule_action_sniff_deserialization() {
        let json = r#"{"action": "sniff"}"#;
        let result: Result<RuleAction, _> = serde_json::from_str(json);
        println!("Sniff result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse sniff action: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_route_rule_with_sniff_action() {
        let json = r#"{"inbound": "tun-in", "action": "sniff"}"#;
        let result: Result<RouteRule, _> = serde_json::from_str(json);
        println!("RouteRule result: {:?}", result);
        assert!(
            result.is_ok(),
            "Failed to parse route rule with sniff: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_sniff_action() {
        let action = RuleAction::Sniff(
            SniffAction::new()
                .with_sniffers(vec!["http".to_string(), "tls".to_string()])
                .with_timeout("500ms"),
        );
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"sniff""#));
        assert!(json.contains(r#""sniffer":["http","tls"]"#));
        assert!(json.contains(r#""timeout":"500ms""#));
    }

    #[test]
    fn test_resolve_action() {
        let action = RuleAction::Resolve(
            ResolveAction::new()
                .with_server("local")
                .with_strategy(DomainStrategy::PreferIpv4),
        );
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"resolve""#));
        assert!(json.contains(r#""server":"local""#));
        assert!(json.contains(r#""strategy":"prefer_ipv4""#));
    }

    #[test]
    fn test_inline_rule_set() {
        let rule = HeadlessRule::new().match_domain_suffix(vec![".cn".to_string()]);
        let rule_set = RuleSet::Inline(InlineRuleSet::new("cn-domains", vec![rule]));
        let json = serde_json::to_string(&rule_set).unwrap();
        assert!(json.contains(r#""type":"inline""#));
        assert!(json.contains(r#""tag":"cn-domains""#));
    }

    #[test]
    fn test_local_rule_set() {
        let rule_set = RuleSet::Local(
            LocalRuleSet::new("geoip-cn", "geoip-cn.srs").with_format(RuleSetFormat::Binary),
        );
        let json = serde_json::to_string(&rule_set).unwrap();
        assert!(json.contains(r#""type":"local""#));
        assert!(json.contains(r#""tag":"geoip-cn""#));
        assert!(json.contains(r#""path":"geoip-cn.srs""#));
        assert!(json.contains(r#""format":"binary""#));
    }

    #[test]
    fn test_remote_rule_set() {
        let rule_set = RuleSet::Remote(
            RemoteRuleSet::new("geosite-cn", "https://example.com/geosite-cn.srs")
                .with_format(RuleSetFormat::Binary)
                .with_update_interval("24h"),
        );
        let json = serde_json::to_string(&rule_set).unwrap();
        assert!(json.contains(r#""type":"remote""#));
        assert!(json.contains(r#""tag":"geosite-cn""#));
        assert!(json.contains(r#""update_interval":"24h""#));
    }

    #[test]
    fn test_route_roundtrip() {
        let route = Route::new()
            .with_final("direct")
            .with_auto_detect_interface()
            .add_rule(
                RouteRule::new()
                    .match_domain_suffix(vec![".cn".to_string()])
                    .with_action(RuleAction::Route(RouteAction::new("direct"))),
            )
            .add_rule_set(RuleSet::Remote(RemoteRuleSet::new(
                "geoip-cn",
                "https://example.com/geoip-cn.srs",
            )));

        let json = serde_json::to_string_pretty(&route).unwrap();
        let parsed: Route = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.final_outbound, Some("direct".to_string()));
        assert!(parsed.auto_detect_interface);
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rule_set.len(), 1);
    }

    #[test]
    fn test_rule_with_multiple_conditions() {
        let rule = RouteRule::new()
            .match_inbound(vec!["mixed-in".to_string()])
            .match_domain_suffix(vec![".google.com".to_string()])
            .match_port(vec![443])
            .with_action(RuleAction::Route(RouteAction::new("proxy")));

        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains(r#""inbound":["mixed-in"]"#));
        assert!(json.contains(r#""domain_suffix":[".google.com"]"#));
        assert!(json.contains(r#""port":[443]"#));
    }

    #[test]
    fn test_headless_rule() {
        let rule = HeadlessRule::new()
            .match_domain(vec!["example.com".to_string()])
            .match_ip_cidr(vec!["10.0.0.0/8".to_string()]);
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains(r#""domain":["example.com"]"#));
        assert!(json.contains(r#""ip_cidr":["10.0.0.0/8"]"#));
    }

    #[test]
    fn test_logical_headless_rule() {
        let rule1 = HeadlessRule::new().match_domain(vec!["a.com".to_string()]);
        let rule2 = HeadlessRule::new().match_domain(vec!["b.com".to_string()]);
        let logical = HeadlessRule::logical(LogicalMode::And, vec![rule1, rule2]);
        let json = serde_json::to_string(&logical).unwrap();
        assert!(json.contains(r#""type":"logical""#));
        assert!(json.contains(r#""mode":"and""#));
    }

    #[test]
    fn test_hijack_dns_action() {
        // HijackDns has no fields, so it serializes as a simple string
        let action = RuleAction::HijackDns;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, r#""hijack-dns""#);
    }

    #[test]
    fn test_bypass_action() {
        let action = RuleAction::Bypass(BypassAction {
            outbound: Some("direct".to_string()),
            ..Default::default()
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"bypass""#));
        assert!(json.contains(r#""outbound":"direct""#));
    }

    #[test]
    fn test_route_options_action() {
        let action = RuleAction::RouteOptions(RouteOptionsAction {
            override_address: Some("1.1.1.1".to_string()),
            override_port: 53,
            tls_fragment: true,
            ..Default::default()
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"route-options""#));
        assert!(json.contains(r#""override_address":"1.1.1.1""#));
        assert!(json.contains(r#""override_port":53"#));
        assert!(json.contains(r#""tls_fragment":true"#));
    }

    #[test]
    fn test_geo_resource() {
        let geo = GeoResource {
            path: Some("geoip.db".to_string()),
            download_url: Some("https://example.com/geoip.db".to_string()),
            download_detour: Some("direct".to_string()),
        };
        let json = serde_json::to_string(&geo).unwrap();
        assert!(json.contains(r#""path":"geoip.db""#));
        assert!(json.contains(r#""download_url""#));
        assert!(json.contains(r#""download_detour":"direct""#));
    }

    #[test]
    fn test_deserialization_from_json() {
        let json = r#"{
            "rules": [
                {
                    "domain_suffix": [".cn"],
                    "action": {
                        "action": "route",
                        "outbound": "direct"
                    }
                }
            ],
            "final": "proxy",
            "auto_detect_interface": true
        }"#;

        let route: Route = serde_json::from_str(json).unwrap();
        assert_eq!(route.final_outbound, Some("proxy".to_string()));
        assert!(route.auto_detect_interface);
        assert_eq!(route.rules.len(), 1);
    }
}

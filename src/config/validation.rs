//! Configuration validation module.
//!
//! This module provides validation functions for sing-box configurations,
//! catching common mistakes before handing the config to sing-box.

use std::collections::{HashMap, HashSet};
use std::fmt;

use tracing::{debug, warn};

use crate::config::SingBoxConfig;
use crate::config::dns::{DnsRule, DnsServer};
use crate::config::outbound::Outbound;
use crate::config::route::{RouteRule, RuleAction, RuleSet};

// ============================================================================
// Error Types
// ============================================================================

/// Configuration validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Circular reference detected in outbound detour chain.
    OutboundCircularReference {
        /// The outbound where the cycle was detected.
        outbound: String,
        /// The cycle path (e.g., `["a", "b", "c", "a"]`).
        cycle: Vec<String>,
    },

    /// Route rule references a non-existent outbound.
    RouteOutboundNotFound {
        /// The rule index (0-based).
        rule_index: usize,
        /// The referenced outbound tag.
        outbound: String,
    },

    /// Route final outbound references a non-existent outbound.
    RouteFinalOutboundNotFound {
        /// The referenced outbound tag.
        outbound: String,
    },

    /// Selector/URLTest outbound references a non-existent outbound.
    SelectorOutboundNotFound {
        /// The selector outbound tag.
        selector: String,
        /// The referenced outbound tag that was not found.
        outbound: String,
    },

    /// DNS rule references a non-existent DNS server.
    DnsServerNotFound {
        /// The rule index (0-based).
        rule_index: usize,
        /// The referenced server tag.
        server: String,
    },

    /// DNS final server references a non-existent DNS server.
    DnsFinalServerNotFound {
        /// The referenced server tag.
        server: String,
    },

    /// Duplicate rule-set tag found.
    DuplicateRuleSetTag {
        /// The duplicated tag.
        tag: String,
    },

    /// Duplicate outbound tag found.
    DuplicateOutboundTag {
        /// The duplicated tag.
        tag: String,
    },

    /// Duplicate DNS server tag found.
    DuplicateDnsServerTag {
        /// The duplicated tag.
        tag: String,
    },

    /// Route rule references a non-existent rule-set.
    RuleSetNotFound {
        /// The rule index (0-based).
        rule_index: usize,
        /// The referenced rule-set tag.
        rule_set: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutboundCircularReference { outbound, cycle } => {
                write!(
                    f,
                    "circular reference detected in outbound '{}': {}",
                    outbound,
                    cycle.join(" -> ")
                )
            }
            Self::RouteOutboundNotFound {
                rule_index,
                outbound,
            } => {
                let rule_num = rule_index + 1;
                write!(
                    f,
                    "route rule #{rule_num} references non-existent outbound '{outbound}'"
                )
            }
            Self::RouteFinalOutboundNotFound { outbound } => {
                write!(
                    f,
                    "route final references non-existent outbound '{outbound}'"
                )
            }
            Self::SelectorOutboundNotFound { selector, outbound } => {
                write!(
                    f,
                    "selector '{selector}' references non-existent outbound '{outbound}'"
                )
            }
            Self::DnsServerNotFound { rule_index, server } => {
                let rule_num = rule_index + 1;
                write!(
                    f,
                    "DNS rule #{rule_num} references non-existent server '{server}'"
                )
            }
            Self::DnsFinalServerNotFound { server } => {
                write!(f, "DNS final references non-existent server '{server}'")
            }
            Self::DuplicateRuleSetTag { tag } => {
                write!(f, "duplicate rule-set tag '{tag}'")
            }
            Self::DuplicateOutboundTag { tag } => {
                write!(f, "duplicate outbound tag '{tag}'")
            }
            Self::DuplicateDnsServerTag { tag } => {
                write!(f, "duplicate DNS server tag '{tag}'")
            }
            Self::RuleSetNotFound {
                rule_index,
                rule_set,
            } => {
                let rule_num = rule_index + 1;
                write!(
                    f,
                    "route rule #{rule_num} references non-existent rule-set '{rule_set}'"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// Validation Result
// ============================================================================

/// Result of configuration validation.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// List of validation errors found.
    pub errors: Vec<ConfigError>,
}

impl ValidationResult {
    /// Create a new empty validation result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if validation passed (no errors).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if validation failed (has errors).
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Get the number of errors.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Add an error to the result.
    pub fn add_error(&mut self, error: ConfigError) {
        self.errors.push(error);
    }

    /// Convert to a Result type.
    ///
    /// # Errors
    ///
    /// Returns the list of errors if validation failed.
    pub fn into_result(self) -> Result<(), Vec<ConfigError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    /// Log all errors using tracing.
    pub fn log_errors(&self) {
        for error in &self.errors {
            warn!(error = %error, "configuration validation error");
        }
    }
}

// ============================================================================
// Validation Implementation
// ============================================================================

impl SingBoxConfig {
    /// Validate the configuration and return a list of errors.
    ///
    /// This method performs various validation checks:
    /// - Outbound circular reference detection
    /// - Route rules reference existing outbounds
    /// - DNS rules reference existing DNS servers
    /// - Rule-set tag uniqueness
    /// - Outbound tag uniqueness
    /// - DNS server tag uniqueness
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        debug!("starting configuration validation");

        // Collect outbound tags
        let outbound_tags = self.collect_outbound_tags(&mut result);
        debug!(count = outbound_tags.len(), "collected outbound tags");

        // Check for circular references in outbounds
        self.check_outbound_cycles(&outbound_tags, &mut result);

        // Collect DNS server tags
        let dns_server_tags = self.collect_dns_server_tags(&mut result);
        debug!(count = dns_server_tags.len(), "collected DNS server tags");

        // Collect rule-set tags
        let rule_set_tags = self.collect_rule_set_tags(&mut result);
        debug!(count = rule_set_tags.len(), "collected rule-set tags");

        // Validate route references
        self.check_route_outbound_refs(&outbound_tags, &rule_set_tags, &mut result);

        // Validate selector/urltest outbound references
        self.check_selector_outbound_refs(&outbound_tags, &mut result);

        // Validate DNS references
        self.check_dns_server_refs(&dns_server_tags, &mut result);

        if result.is_ok() {
            debug!("configuration validation passed");
        } else {
            warn!(
                error_count = result.error_count(),
                "configuration validation failed"
            );
            result.log_errors();
        }

        result
    }

    /// Collect all outbound tags and check for duplicates.
    fn collect_outbound_tags(&self, result: &mut ValidationResult) -> HashSet<String> {
        let mut tags = HashSet::new();

        for outbound in &self.outbounds {
            if let Some(tag) = get_outbound_tag(outbound)
                && !tags.insert(tag.clone())
            {
                result.add_error(ConfigError::DuplicateOutboundTag { tag });
            }
        }

        tags
    }

    /// Collect all DNS server tags and check for duplicates.
    fn collect_dns_server_tags(&self, result: &mut ValidationResult) -> HashSet<String> {
        let mut tags = HashSet::new();

        if let Some(dns) = &self.dns {
            for server in &dns.servers {
                let tag = get_dns_server_tag(server);
                if !tags.insert(tag.clone()) {
                    result.add_error(ConfigError::DuplicateDnsServerTag { tag });
                }
            }
        }

        tags
    }

    /// Collect all rule-set tags and check for duplicates.
    fn collect_rule_set_tags(&self, result: &mut ValidationResult) -> HashSet<String> {
        let mut tags = HashSet::new();

        if let Some(route) = &self.route {
            for rule_set in &route.rule_set {
                let tag = get_rule_set_tag(rule_set);
                if !tags.insert(tag.clone()) {
                    result.add_error(ConfigError::DuplicateRuleSetTag { tag });
                }
            }
        }

        tags
    }

    /// Check for circular references in outbound detour chains.
    fn check_outbound_cycles(
        &self,
        outbound_tags: &HashSet<String>,
        result: &mut ValidationResult,
    ) {
        // Build a map of outbound tag -> detour target
        let mut detour_map: HashMap<String, String> = HashMap::new();

        for outbound in &self.outbounds {
            if let (Some(tag), Some(detour)) =
                (get_outbound_tag(outbound), get_outbound_detour(outbound))
            {
                detour_map.insert(tag, detour);
            }
        }

        // Also check selector/urltest outbounds for their referenced outbounds
        // (they form implicit detour relationships)
        for outbound in &self.outbounds {
            if let Some(tag) = get_outbound_tag(outbound) {
                // For each outbound that has a detour, check for cycles
                if detour_map.contains_key(&tag) {
                    let mut visited = HashSet::new();
                    let mut path = vec![tag.clone()];
                    let mut current = tag.clone();

                    while let Some(next) = detour_map.get(&current) {
                        if !outbound_tags.contains(next) {
                            // Target doesn't exist, skip (will be caught by other validation)
                            break;
                        }

                        if visited.contains(next) {
                            // Found a cycle
                            path.push(next.clone());
                            result.add_error(ConfigError::OutboundCircularReference {
                                outbound: tag.clone(),
                                cycle: path,
                            });
                            break;
                        }

                        visited.insert(next.clone());
                        path.push(next.clone());
                        current = next.clone();
                    }
                }
            }
        }
    }

    /// Check that route rules reference existing outbounds and rule-sets.
    fn check_route_outbound_refs(
        &self,
        outbound_tags: &HashSet<String>,
        rule_set_tags: &HashSet<String>,
        result: &mut ValidationResult,
    ) {
        if let Some(route) = &self.route {
            // Check final outbound
            if let Some(final_outbound) = &route.final_outbound
                && !outbound_tags.contains(final_outbound)
            {
                result.add_error(ConfigError::RouteFinalOutboundNotFound {
                    outbound: final_outbound.clone(),
                });
            }

            // Check each rule
            for (index, rule) in route.rules.iter().enumerate() {
                check_route_rule_refs(rule, index, outbound_tags, rule_set_tags, result);
            }
        }
    }

    /// Check that DNS rules reference existing DNS servers.
    fn check_dns_server_refs(&self, server_tags: &HashSet<String>, result: &mut ValidationResult) {
        let Some(dns) = &self.dns else {
            return;
        };

        // Check final server
        if let Some(final_server) = &dns.r#final
            && !server_tags.contains(final_server)
        {
            result.add_error(ConfigError::DnsFinalServerNotFound {
                server: final_server.clone(),
            });
        }

        // Check each rule
        for (index, rule) in dns.rules.iter().enumerate() {
            if let Some(server) = get_dns_rule_server(rule)
                && !server_tags.contains(&server)
            {
                result.add_error(ConfigError::DnsServerNotFound {
                    rule_index: index,
                    server,
                });
            }
        }
    }

    /// Check that selector/urltest outbounds reference existing outbounds.
    fn check_selector_outbound_refs(
        &self,
        outbound_tags: &HashSet<String>,
        result: &mut ValidationResult,
    ) {
        for outbound in &self.outbounds {
            match outbound {
                Outbound::Selector(selector) => {
                    let selector_tag = selector.tag.clone().unwrap_or_else(|| "unnamed".into());
                    for referenced in &selector.outbounds {
                        if !outbound_tags.contains(referenced) {
                            result.add_error(ConfigError::SelectorOutboundNotFound {
                                selector: selector_tag.clone(),
                                outbound: referenced.clone(),
                            });
                        }
                    }
                }
                Outbound::UrlTest(urltest) => {
                    let urltest_tag = urltest.tag.clone().unwrap_or_else(|| "unnamed".into());
                    for referenced in &urltest.outbounds {
                        if !outbound_tags.contains(referenced) {
                            result.add_error(ConfigError::SelectorOutboundNotFound {
                                selector: urltest_tag.clone(),
                                outbound: referenced.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check references in a single route rule.
fn check_route_rule_refs(
    rule: &RouteRule,
    index: usize,
    outbound_tags: &HashSet<String>,
    rule_set_tags: &HashSet<String>,
    result: &mut ValidationResult,
) {
    // Check legacy outbound field
    if let Some(outbound) = &rule.outbound
        && !outbound_tags.contains(outbound)
    {
        result.add_error(ConfigError::RouteOutboundNotFound {
            rule_index: index,
            outbound: outbound.clone(),
        });
    }

    // Check action outbound
    if let Some(action) = &rule.action
        && let Some(outbound) = get_rule_action_outbound(action)
        && !outbound_tags.contains(&outbound)
    {
        result.add_error(ConfigError::RouteOutboundNotFound {
            rule_index: index,
            outbound,
        });
    }

    // Check rule-set references
    for rule_set in &rule.rule_set {
        if !rule_set_tags.contains(rule_set) {
            result.add_error(ConfigError::RuleSetNotFound {
                rule_index: index,
                rule_set: rule_set.clone(),
            });
        }
    }

    // Check nested rules (for logical rules)
    for nested_rule in &rule.rules {
        check_route_rule_refs(nested_rule, index, outbound_tags, rule_set_tags, result);
    }
}

/// Get the tag from an outbound.
fn get_outbound_tag(outbound: &Outbound) -> Option<String> {
    match outbound {
        Outbound::Direct(o) => o.tag.clone(),
        Outbound::Block(o) => o.tag.clone(),
        Outbound::Socks(o) => o.tag.clone(),
        Outbound::Http(o) => o.tag.clone(),
        Outbound::Shadowsocks(o) => o.tag.clone(),
        Outbound::VMess(o) => o.tag.clone(),
        Outbound::Trojan(o) => o.tag.clone(),
        Outbound::WireGuard(o) => o.tag.clone(),
        Outbound::Hysteria(o) => o.tag.clone(),
        Outbound::VLess(o) => o.tag.clone(),
        Outbound::ShadowTls(o) => o.tag.clone(),
        Outbound::Tuic(o) => o.tag.clone(),
        Outbound::Hysteria2(o) => o.tag.clone(),
        Outbound::AnyTls(o) => o.tag.clone(),
        Outbound::Tor(o) => o.tag.clone(),
        Outbound::Ssh(o) => o.tag.clone(),
        Outbound::Dns(o) => o.tag.clone(),
        Outbound::Selector(o) => o.tag.clone(),
        Outbound::UrlTest(o) => o.tag.clone(),
        Outbound::Naive(o) => o.tag.clone(),
    }
}

/// Get the detour from an outbound's dial fields.
fn get_outbound_detour(outbound: &Outbound) -> Option<String> {
    match outbound {
        Outbound::Direct(o) => o.dial.detour.clone(),
        Outbound::Socks(o) => o.dial.detour.clone(),
        Outbound::Http(o) => o.dial.detour.clone(),
        Outbound::Shadowsocks(o) => o.dial.detour.clone(),
        Outbound::VMess(o) => o.dial.detour.clone(),
        Outbound::Trojan(o) => o.dial.detour.clone(),
        Outbound::WireGuard(o) => o.dial.detour.clone(),
        Outbound::Hysteria(o) => o.dial.detour.clone(),
        Outbound::VLess(o) => o.dial.detour.clone(),
        Outbound::ShadowTls(o) => o.dial.detour.clone(),
        Outbound::Tuic(o) => o.dial.detour.clone(),
        Outbound::Hysteria2(o) => o.dial.detour.clone(),
        Outbound::AnyTls(o) => o.dial.detour.clone(),
        Outbound::Tor(o) => o.dial.detour.clone(),
        Outbound::Ssh(o) => o.dial.detour.clone(),
        Outbound::Naive(o) => o.dial.detour.clone(),
        // These don't have dial fields
        Outbound::Block(_) | Outbound::Dns(_) | Outbound::Selector(_) | Outbound::UrlTest(_) => {
            None
        }
    }
}

/// Get the tag from a DNS server.
fn get_dns_server_tag(server: &DnsServer) -> String {
    match server {
        DnsServer::Legacy(s) => s.tag.clone(),
        DnsServer::Local(s) => s.tag.clone(),
        DnsServer::Hosts(s) => s.tag.clone(),
        DnsServer::Tcp(s) => s.tag.clone(),
        DnsServer::Udp(s) => s.tag.clone(),
        DnsServer::Tls(s) => s.tag.clone(),
        DnsServer::Quic(s) => s.tag.clone(),
        DnsServer::Https(s) => s.tag.clone(),
        DnsServer::H3(s) => s.tag.clone(),
        DnsServer::Dhcp(s) => s.tag.clone(),
        DnsServer::FakeIp(s) => s.tag.clone(),
        DnsServer::Tailscale(s) => s.tag.clone(),
        DnsServer::Resolved(s) => s.tag.clone(),
    }
}

/// Get the server tag from a DNS rule action.
fn get_dns_rule_server(rule: &DnsRule) -> Option<String> {
    match rule {
        DnsRule::Default(r) => {
            // Check action field
            if let crate::config::dns::DnsRuleAction::Route(route) = &r.action
                && !route.server.is_empty()
            {
                return Some(route.server.clone());
            }
            // Fall back to legacy outbound field (first item)
            r.outbound.first().cloned()
        }
        DnsRule::Logical(r) => {
            if let crate::config::dns::DnsRuleAction::Route(route) = &r.action
                && !route.server.is_empty()
            {
                return Some(route.server.clone());
            }
            None
        }
    }
}

/// Get the tag from a rule-set.
fn get_rule_set_tag(rule_set: &RuleSet) -> String {
    match rule_set {
        RuleSet::Inline(rs) => rs.tag.clone(),
        RuleSet::Local(rs) => rs.tag.clone(),
        RuleSet::Remote(rs) => rs.tag.clone(),
    }
}

/// Get the outbound from a rule action.
fn get_rule_action_outbound(action: &RuleAction) -> Option<String> {
    match action {
        RuleAction::Route(route) => Some(route.outbound.clone()),
        RuleAction::Bypass(bypass) => bypass.outbound.clone(),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::{DefaultDnsRule, Dns, LocalDnsServer, UdpDnsServer};
    use crate::config::outbound::{BlockOutbound, DirectOutbound, SelectorOutbound, SocksOutbound};
    use crate::config::route::{InlineRuleSet, LocalRuleSet, Route, RouteAction};
    use crate::config::shared::DialFields;

    #[test]
    fn test_valid_config_passes_validation() {
        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .build();

        let result = config.validate();
        assert!(result.is_ok());
        assert_eq!(result.error_count(), 0);
    }

    #[test]
    fn test_duplicate_outbound_tag() {
        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .build();

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::DuplicateOutboundTag { tag } if tag == "direct"
        )));
    }

    #[test]
    fn test_route_final_outbound_not_found() {
        let config = SingBoxConfig {
            route: Some(Route::new().with_final("nonexistent")),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::RouteFinalOutboundNotFound { outbound } if outbound == "nonexistent"
        )));
    }

    #[test]
    fn test_route_rule_outbound_not_found() {
        let config = SingBoxConfig {
            route: Some(Route::new().add_rule(
                RouteRule::new().with_action(RuleAction::Route(RouteAction::new("nonexistent"))),
            )),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::RouteOutboundNotFound { outbound, .. } if outbound == "nonexistent"
        )));
    }

    #[test]
    fn test_selector_outbound_not_found() {
        let config = SingBoxConfig {
            outbounds: vec![
                Outbound::Direct(DirectOutbound::new("direct")),
                Outbound::Selector(SelectorOutbound::new(
                    "select",
                    vec!["direct".to_string(), "nonexistent".to_string()],
                )),
            ],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::SelectorOutboundNotFound { outbound, .. } if outbound == "nonexistent"
        )));
    }

    #[test]
    fn test_outbound_circular_reference() {
        // Create outbound a -> b -> c -> a
        let mut outbound_a = SocksOutbound::new("a", "127.0.0.1", 1080);
        outbound_a.dial = DialFields {
            detour: Some("b".to_string()),
            ..Default::default()
        };

        let mut outbound_b = SocksOutbound::new("b", "127.0.0.1", 1081);
        outbound_b.dial = DialFields {
            detour: Some("c".to_string()),
            ..Default::default()
        };

        let mut outbound_c = SocksOutbound::new("c", "127.0.0.1", 1082);
        outbound_c.dial = DialFields {
            detour: Some("a".to_string()),
            ..Default::default()
        };

        let config = SingBoxConfig {
            outbounds: vec![
                Outbound::Socks(outbound_a),
                Outbound::Socks(outbound_b),
                Outbound::Socks(outbound_c),
            ],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ConfigError::OutboundCircularReference { .. }))
        );
    }

    #[test]
    fn test_valid_outbound_chain() {
        // Create valid chain: a -> b -> c (no cycle)
        let mut outbound_a = SocksOutbound::new("a", "127.0.0.1", 1080);
        outbound_a.dial = DialFields {
            detour: Some("b".to_string()),
            ..Default::default()
        };

        let mut outbound_b = SocksOutbound::new("b", "127.0.0.1", 1081);
        outbound_b.dial = DialFields {
            detour: Some("c".to_string()),
            ..Default::default()
        };

        let outbound_c = SocksOutbound::new("c", "127.0.0.1", 1082);

        let config = SingBoxConfig {
            outbounds: vec![
                Outbound::Socks(outbound_a),
                Outbound::Socks(outbound_b),
                Outbound::Socks(outbound_c),
            ],
            ..Default::default()
        };

        let result = config.validate();
        // Should not have circular reference errors
        assert!(
            !result
                .errors
                .iter()
                .any(|e| matches!(e, ConfigError::OutboundCircularReference { .. }))
        );
    }

    #[test]
    fn test_dns_server_not_found() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer::Local(LocalDnsServer {
                    tag: "local".to_string(),
                })],
                rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                    outbound: vec!["nonexistent".to_string()],
                    ..Default::default()
                }))],
                r#final: Some("local".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::DnsServerNotFound { server, .. } if server == "nonexistent"
        )));
    }

    #[test]
    fn test_dns_final_server_not_found() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![DnsServer::Local(LocalDnsServer {
                    tag: "local".to_string(),
                })],
                r#final: Some("nonexistent".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::DnsFinalServerNotFound { server } if server == "nonexistent"
        )));
    }

    #[test]
    fn test_duplicate_dns_server_tag() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                servers: vec![
                    DnsServer::Local(LocalDnsServer {
                        tag: "dns".to_string(),
                    }),
                    DnsServer::Udp(UdpDnsServer {
                        tag: "dns".to_string(),
                        server: "8.8.8.8".to_string(),
                        ..Default::default()
                    }),
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::DuplicateDnsServerTag { tag } if tag == "dns"
        )));
    }

    #[test]
    fn test_duplicate_rule_set_tag() {
        let config = SingBoxConfig {
            route: Some(
                Route::new()
                    .add_rule_set(RuleSet::Inline(InlineRuleSet::new("rules", vec![])))
                    .add_rule_set(RuleSet::Local(LocalRuleSet::new("rules", "rules.json"))),
            ),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::DuplicateRuleSetTag { tag } if tag == "rules"
        )));
    }

    #[test]
    fn test_rule_set_not_found() {
        let config = SingBoxConfig {
            route: Some(
                Route::new().add_rule(RouteRule::new().match_rule_set(vec!["nonexistent".into()])),
            ),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::RuleSetNotFound { rule_set, .. } if rule_set == "nonexistent"
        )));
    }

    #[test]
    fn test_config_error_display() {
        let error = ConfigError::OutboundCircularReference {
            outbound: "a".to_string(),
            cycle: vec!["a".to_string(), "b".to_string(), "a".to_string()],
        };
        assert_eq!(
            error.to_string(),
            "circular reference detected in outbound 'a': a -> b -> a"
        );

        let error = ConfigError::RouteOutboundNotFound {
            rule_index: 0,
            outbound: "proxy".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "route rule #1 references non-existent outbound 'proxy'"
        );
    }

    #[test]
    fn test_validation_result_into_result() {
        let result = ValidationResult::new();
        assert!(result.into_result().is_ok());

        let mut result = ValidationResult::new();
        result.add_error(ConfigError::DuplicateOutboundTag {
            tag: "test".to_string(),
        });
        let err = result.into_result().unwrap_err();
        assert_eq!(err.len(), 1);
    }

    #[test]
    fn test_complete_valid_config() {
        // Build a complete, valid configuration
        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .outbound(Outbound::Selector(SelectorOutbound::new(
                "select",
                vec!["direct".to_string()],
            )))
            .route(
                Route::new()
                    .with_final("direct")
                    .add_rule_set(RuleSet::Inline(InlineRuleSet::new("my-rules", vec![])))
                    .add_rule(
                        RouteRule::new()
                            .match_rule_set(vec!["my-rules".into()])
                            .with_action(RuleAction::Route(RouteAction::new("block"))),
                    ),
            )
            .dns(Dns {
                servers: vec![
                    DnsServer::Local(LocalDnsServer {
                        tag: "local".to_string(),
                    }),
                    DnsServer::Udp(UdpDnsServer {
                        tag: "google".to_string(),
                        server: "8.8.8.8".to_string(),
                        ..Default::default()
                    }),
                ],
                r#final: Some("local".to_string()),
                ..Default::default()
            })
            .build();

        let result = config.validate();
        assert!(
            result.is_ok(),
            "Expected valid config, got errors: {:?}",
            result.errors
        );
    }
}

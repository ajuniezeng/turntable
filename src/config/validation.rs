//! Configuration validation module.
//!
//! This module provides validation functions for sing-box configurations,
//! catching common mistakes before handing the config to sing-box.

use std::collections::{HashMap, HashSet};
use std::fmt;

use tracing::{debug, info, warn};

use crate::config::SingBoxConfig;
use crate::config::dns::{DnsRule, DnsServer};
use crate::config::inbound::Inbound;
use crate::config::outbound::Outbound;
use crate::config::route::{RouteRule, RuleAction, RuleSet};
use crate::config::version::SingBoxVersion;

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

    /// Selector default references a non-existent outbound.
    SelectorDefaultOutboundNotFound {
        /// The selector outbound tag.
        selector: String,
        /// The referenced default outbound tag that was not found.
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

    /// DNS rule is invalid for the target version or rule semantics.
    InvalidDnsRule {
        /// The rule index (0-based).
        rule_index: usize,
        /// Details about the invalid rule.
        message: String,
    },
}

// ============================================================================
// Warning Types
// ============================================================================

/// Configuration validation warning.
///
/// Warnings indicate potential issues that won't prevent the config from working,
/// but may cause unexpected behavior (e.g., one field being ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarning {
    /// Conflicting fields in Hysteria outbound (server_port vs server_ports).
    HysteriaServerPortConflict {
        /// The outbound tag.
        outbound: String,
    },

    /// Conflicting fields in Hysteria2 outbound (server_port vs server_ports).
    Hysteria2ServerPortConflict {
        /// The outbound tag.
        outbound: String,
    },

    /// Conflicting fields in Route (default_interface vs default_network_strategy).
    RouteInterfaceStrategyConflict,

    /// Conflicting fields in DialFields (bind_interface/inet*_bind_address vs network_strategy).
    DialFieldsBindStrategyConflict {
        /// The outbound tag (if applicable).
        outbound: Option<String>,
    },

    // ========================================================================
    // Version-specific warnings
    // ========================================================================
    /// Feature requires a newer sing-box version.
    UnsupportedFeature {
        /// The feature that is not supported.
        feature: String,
        /// The minimum version required.
        min_version: String,
        /// The target version being used.
        target_version: String,
    },

    /// Feature is deprecated in the target version.
    DeprecatedFeature {
        /// The feature that is deprecated.
        feature: String,
        /// The version where it was deprecated/removed.
        deprecated_in: String,
        /// The target version being used.
        target_version: String,
        /// Optional suggestion for replacement.
        suggestion: Option<String>,
    },
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HysteriaServerPortConflict { outbound } => {
                write!(
                    f,
                    "hysteria outbound '{}': both 'server_port' and 'server_ports' are set; 'server_port' will be ignored",
                    outbound
                )
            }
            Self::Hysteria2ServerPortConflict { outbound } => {
                write!(
                    f,
                    "hysteria2 outbound '{}': both 'server_port' and 'server_ports' are set; 'server_port' will be ignored",
                    outbound
                )
            }
            Self::RouteInterfaceStrategyConflict => {
                write!(
                    f,
                    "route: both 'default_interface' and 'default_network_strategy' are set; they conflict with each other"
                )
            }
            Self::DialFieldsBindStrategyConflict { outbound } => {
                if let Some(tag) = outbound {
                    write!(
                        f,
                        "outbound '{}': 'network_strategy' conflicts with 'bind_interface', 'inet4_bind_address', or 'inet6_bind_address'",
                        tag
                    )
                } else {
                    write!(
                        f,
                        "'network_strategy' conflicts with 'bind_interface', 'inet4_bind_address', or 'inet6_bind_address'"
                    )
                }
            }
            Self::UnsupportedFeature {
                feature,
                min_version,
                target_version,
            } => {
                write!(
                    f,
                    "'{}' requires sing-box {} or later, but target version is {}",
                    feature, min_version, target_version
                )
            }
            Self::DeprecatedFeature {
                feature,
                deprecated_in,
                target_version,
                suggestion,
            } => {
                if let Some(suggestion) = suggestion {
                    write!(
                        f,
                        "'{}' is deprecated/removed in sing-box {} (target: {}); {}",
                        feature, deprecated_in, target_version, suggestion
                    )
                } else {
                    write!(
                        f,
                        "'{}' is deprecated/removed in sing-box {} (target: {})",
                        feature, deprecated_in, target_version
                    )
                }
            }
        }
    }
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
            Self::SelectorDefaultOutboundNotFound { selector, outbound } => {
                write!(
                    f,
                    "selector '{selector}' default references non-existent outbound '{outbound}'"
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
            Self::InvalidDnsRule {
                rule_index,
                message,
            } => {
                let rule_num = rule_index + 1;
                write!(f, "DNS rule #{rule_num} is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

fn dns_rule_has_response_fields(rule: &crate::config::dns::DefaultDnsRule) -> bool {
    rule.response_rcode.is_some()
        || !rule.response_answer.is_empty()
        || !rule.response_ns.is_empty()
        || !rule.response_extra.is_empty()
}

fn dns_rule_action_uses_legacy_strategy(action: &crate::config::dns::DnsRuleAction) -> bool {
    match action {
        crate::config::dns::DnsRuleAction::Legacy(action) => action.strategy.is_some(),
        crate::config::dns::DnsRuleAction::Tagged(
            crate::config::dns::TaggedDnsRuleAction::Route(action),
        ) => action.strategy.is_some(),
        _ => false,
    }
}

fn dns_rule_uses_legacy_address_filters(rule: &crate::config::dns::DefaultDnsRule) -> bool {
    (!rule.ip_cidr.is_empty() || rule.ip_is_private) && !rule.match_response
        || rule.rule_set_ip_cidr_accept_empty
        || dns_rule_action_uses_legacy_strategy(&rule.action)
}

fn dns_rule_action_is_evaluate(rule: &DnsRule) -> bool {
    match rule {
        DnsRule::Default(rule) => matches!(
            &rule.action,
            crate::config::dns::DnsRuleAction::Tagged(
                crate::config::dns::TaggedDnsRuleAction::Evaluate(_)
            )
        ),
        DnsRule::Logical(rule) => matches!(
            &rule.action,
            crate::config::dns::DnsRuleAction::Tagged(
                crate::config::dns::TaggedDnsRuleAction::Evaluate(_)
            )
        ),
    }
}

fn dns_rule_has_ip_version_or_query_type(rule: &DnsRule) -> bool {
    match rule {
        DnsRule::Default(rule) => rule.ip_version.is_some() || !rule.query_type.is_empty(),
        DnsRule::Logical(rule) => rule.rules.iter().any(dns_rule_has_ip_version_or_query_type),
    }
}

fn collect_dns_rule_set_refs(rule: &DnsRule, refs: &mut HashSet<String>) {
    match rule {
        DnsRule::Default(rule) => {
            refs.extend(rule.rule_set.iter().cloned());
        }
        DnsRule::Logical(rule) => {
            for nested_rule in &rule.rules {
                collect_dns_rule_set_refs(nested_rule, refs);
            }
        }
    }
}

fn rule_set_contains_query_type(rule_set: &RuleSet) -> bool {
    match rule_set {
        RuleSet::Inline(rule_set) => rule_set.rules.iter().any(headless_rule_contains_query_type),
        RuleSet::Local(_) | RuleSet::Remote(_) => false,
    }
}

fn headless_rule_contains_query_type(rule: &crate::config::route::HeadlessRule) -> bool {
    !rule.query_type.is_empty() || rule.rules.iter().any(headless_rule_contains_query_type)
}

// ============================================================================
// Validation Result
// ============================================================================

/// Result of configuration validation.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// List of validation errors found.
    pub errors: Vec<ConfigError>,
    /// List of validation warnings found.
    pub warnings: Vec<ConfigWarning>,
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

    /// Add a warning to the result.
    pub fn add_warning(&mut self, warning: ConfigWarning) {
        self.warnings.push(warning);
    }

    /// Get the number of warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// Check if there are any warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
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

    /// Log all warnings using tracing.
    pub fn log_warnings(&self) {
        for warning in &self.warnings {
            info!(warning = %warning, "configuration validation warning");
        }
    }

    /// Log all errors and warnings.
    pub fn log_all(&self) {
        self.log_errors();
        self.log_warnings();
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
    /// - Conflicting field detection (warnings)
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        self.validate_for_version(&SingBoxVersion::latest())
    }

    /// Validate the configuration against a specific sing-box version.
    ///
    /// This method performs all validation checks from `validate()` plus
    /// version-specific warnings for unsupported or deprecated features.
    #[must_use]
    pub fn validate_for_version(&self, version: &SingBoxVersion) -> ValidationResult {
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

        // Check for conflicting fields (warnings)
        self.check_field_conflicts(&mut result);

        // Check for version-specific issues
        self.check_version_compatibility(version, &mut result);

        if result.is_ok() {
            debug!("configuration validation passed");
        } else {
            warn!(
                error_count = result.error_count(),
                "configuration validation failed"
            );
            result.log_errors();
        }

        // Log warnings separately
        if result.has_warnings() {
            info!(
                warning_count = result.warning_count(),
                "configuration has conflicting fields"
            );
            result.log_warnings();
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
                    // Check default outbound reference
                    if let Some(default) = &selector.default
                        && !outbound_tags.contains(default)
                    {
                        result.add_error(ConfigError::SelectorDefaultOutboundNotFound {
                            selector: selector_tag.clone(),
                            outbound: default.clone(),
                        });
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

    /// Check for version-specific compatibility issues.
    fn check_version_compatibility(&self, version: &SingBoxVersion, result: &mut ValidationResult) {
        let version_str = version.to_string();

        // Check endpoints (since 1.11)
        if !self.endpoints.is_empty() && !version.supports_endpoints() {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "endpoints".to_string(),
                min_version: "1.11".to_string(),
                target_version: version_str.clone(),
            });
        }

        // Check for Tailscale endpoints (since 1.12)
        for endpoint in &self.endpoints {
            if matches!(endpoint, crate::config::endpoint::Endpoint::Tailscale(_))
                && !version.supports_tailscale()
            {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "tailscale endpoint".to_string(),
                    min_version: "1.12".to_string(),
                    target_version: version_str.clone(),
                });
                break; // Only warn once
            }
        }

        // Check services (since 1.12)
        if !self.services.is_empty() && !version.supports_services() {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "services".to_string(),
                min_version: "1.12".to_string(),
                target_version: version_str.clone(),
            });
        }

        // Check certificate section (since 1.12)
        if self.certificate.is_some() && !version.supports_certificate() {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "certificate".to_string(),
                min_version: "1.12".to_string(),
                target_version: version_str.clone(),
            });
        }

        // Check certificate providers (since 1.14)
        if !self.certificate_providers.is_empty() && version < &SingBoxVersion::new(1, 14) {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "certificate_providers".to_string(),
                min_version: "1.14".to_string(),
                target_version: version_str.clone(),
            });
        }

        // Check http_clients (since 1.14)
        if !self.http_clients.is_empty() && version < &SingBoxVersion::new(1, 14) {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "http_clients".to_string(),
                min_version: "1.14".to_string(),
                target_version: version_str.clone(),
            });
        }

        // Check certificate provider http_client fields (since 1.14)
        if version < &SingBoxVersion::new(1, 14) {
            for provider in &self.certificate_providers {
                let has_http_client = match provider {
                    crate::config::shared::CertificateProvider::Acme(p) => {
                        p.http_client.is_some()
                    }
                    crate::config::shared::CertificateProvider::Tailscale(p) => {
                        p.http_client.is_some()
                    }
                    crate::config::shared::CertificateProvider::CloudflareOriginCa(p) => {
                        p.http_client.is_some()
                    }
                };
                if has_http_client {
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: "certificate_provider.http_client".to_string(),
                        min_version: "1.14".to_string(),
                        target_version: version_str.clone(),
                    });
                    break;
                }
            }
        }

        // Check route-level features
        if let Some(route) = &self.route {
            // Check network_strategy (since 1.11)
            if route.default_network_strategy.is_some() && !version.supports_network_strategy() {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "route.default_network_strategy".to_string(),
                    min_version: "1.11".to_string(),
                    target_version: version_str.clone(),
                });
            }

            // Check default_domain_resolver (since 1.12)
            if route.default_domain_resolver.is_some()
                && !version.supports_default_domain_resolver()
            {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "route.default_domain_resolver".to_string(),
                    min_version: "1.12".to_string(),
                    target_version: version_str.clone(),
                });
            }

            // Check route.default_http_client (since 1.14)
            if route.default_http_client.is_some() && version < &SingBoxVersion::new(1, 14) {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "route.default_http_client".to_string(),
                    min_version: "1.14".to_string(),
                    target_version: version_str.clone(),
                });
            }

            // Check rule-set http_client (since 1.14) and download_detour (deprecated in 1.14)
            for rs in &route.rule_set {
                if let crate::config::route::RuleSet::Remote(remote) = rs {
                    if remote.http_client.is_some() && version < &SingBoxVersion::new(1, 14) {
                        result.add_warning(ConfigWarning::UnsupportedFeature {
                            feature: format!("rule_set '{}' http_client", remote.tag),
                            min_version: "1.14".to_string(),
                            target_version: version_str.clone(),
                        });
                    }
                    if remote.download_detour.is_some() && version >= &SingBoxVersion::new(1, 14) {
                        result.add_warning(ConfigWarning::DeprecatedFeature {
                            feature: format!("rule_set '{}' download_detour", remote.tag),
                            deprecated_in: "1.14".to_string(),
                            target_version: version_str.clone(),
                            suggestion: Some(
                                "use rule_set.http_client or route.default_http_client instead"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }

            // Check for deprecated geoip/geosite usage
            for (index, rule) in route.rules.iter().enumerate() {
                self.check_route_rule_version_compatibility(
                    rule,
                    index,
                    version,
                    &version_str,
                    result,
                );
            }
        }

        // Check outbound-specific version features
        for outbound in &self.outbounds {
            self.check_outbound_version_compatibility(outbound, version, &version_str, result);
        }

        // Check inbound-specific version features
        for inbound in &self.inbounds {
            self.check_inbound_version_compatibility(inbound, version, &version_str, result);
        }

        // Check DNS version features
        if let Some(dns) = &self.dns {
            self.check_dns_version_compatibility(dns, version, &version_str, result);
        }

        // Check experimental 1.14 features
        if let Some(experimental) = &self.experimental
            && let Some(cache_file) = &experimental.cache_file
            && cache_file.store_dns
            && version < &SingBoxVersion::new(1, 14)
        {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "experimental.cache_file.store_dns".to_string(),
                min_version: "1.14".to_string(),
                target_version: version_str.clone(),
            });
        }
    }

    /// Check route rule version compatibility.
    fn check_route_rule_version_compatibility(
        &self,
        rule: &RouteRule,
        _index: usize,
        version: &SingBoxVersion,
        version_str: &str,
        result: &mut ValidationResult,
    ) {
        // Check deprecated geoip/geosite (removed in 1.12)
        if !rule.geosite.is_empty() && !version.supports_geoip_geosite() {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "route rule geosite".to_string(),
                deprecated_in: "1.12".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("use rule_set with geosite sources instead".to_string()),
            });
        }

        if !rule.geoip.is_empty() && !version.supports_geoip_geosite() {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "route rule geoip".to_string(),
                deprecated_in: "1.12".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("use rule_set with geoip sources instead".to_string()),
            });
        }

        if !rule.source_geoip.is_empty() && !version.supports_geoip_geosite() {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "route rule source_geoip".to_string(),
                deprecated_in: "1.12".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("use rule_set with geoip sources instead".to_string()),
            });
        }

        // Check nested rules recursively
        for nested_rule in &rule.rules {
            self.check_route_rule_version_compatibility(
                nested_rule,
                _index,
                version,
                version_str,
                result,
            );
        }
    }

    /// Check outbound version compatibility.
    fn check_outbound_version_compatibility(
        &self,
        outbound: &Outbound,
        version: &SingBoxVersion,
        version_str: &str,
        result: &mut ValidationResult,
    ) {
        match outbound {
            Outbound::Hysteria(h) => {
                // server_ports requires 1.12
                if !h.server_ports.is_empty() && !version.supports_hysteria_port_hopping() {
                    let tag = h.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria outbound '{}' server_ports", tag),
                        min_version: "1.12".to_string(),
                        target_version: version_str.to_string(),
                    });
                }

                let tag = h.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                if h.quic.is_set() && version < &SingBoxVersion::new(1, 14) {
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria outbound '{}' QUIC tuning fields", tag),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                }
                if version >= &SingBoxVersion::new(1, 14)
                    && (h.recv_window_conn.is_some()
                        || h.recv_window.is_some()
                        || h.disable_mtu_discovery)
                {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: format!("hysteria outbound '{}' legacy QUIC tuning", tag),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "use stream_receive_window, connection_receive_window, disable_path_mtu_discovery"
                                .to_string(),
                        ),
                    });
                }
            }
            Outbound::Hysteria2(h2) => {
                // server_ports requires 1.11
                if !h2.server_ports.is_empty() && !version.supports_hysteria2_port_hopping() {
                    let tag = h2.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria2 outbound '{}' server_ports", tag),
                        min_version: "1.11".to_string(),
                        target_version: version_str.to_string(),
                    });
                }

                if (h2.hop_interval_max.is_some() || h2.bbr_profile.is_some())
                    && version < &SingBoxVersion::new(1, 14)
                {
                    let tag = h2.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria2 outbound '{}' 1.14 fields", tag),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                }

                if h2.quic.is_set() && version < &SingBoxVersion::new(1, 14) {
                    let tag = h2.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria2 outbound '{}' QUIC tuning fields", tag),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                }
            }
            Outbound::Tuic(t) => {
                if t.quic.is_set() && version < &SingBoxVersion::new(1, 14) {
                    let tag = t.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("tuic outbound '{}' QUIC tuning fields", tag),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                }
            }
            _ => {}
        }

        // Check TLS 1.14 fields (engine, spoof, spoof_method) on outbounds that carry TLS.
        let tls = match outbound {
            Outbound::Http(o) => o.tls.as_ref(),
            Outbound::Trojan(o) => o.tls.as_ref(),
            Outbound::VMess(o) => o.tls.as_ref(),
            Outbound::VLess(o) => o.tls.as_ref(),
            Outbound::Hysteria(o) => o.tls.as_ref(),
            Outbound::Hysteria2(o) => o.tls.as_ref(),
            Outbound::Tuic(o) => o.tls.as_ref(),
            Outbound::AnyTls(o) => o.tls.as_ref(),
            Outbound::Naive(o) => o.tls.as_ref(),
            _ => None,
        };
        if let Some(tls) = tls {
            let tag = get_outbound_tag(outbound).unwrap_or_else(|| "<unnamed>".to_string());
            let context = format!("outbound '{}'", tag);
            self.check_outbound_tls_114(tls, version, version_str, &context, result);
        }

        // Check dial fields network_strategy (since 1.11)
        if !version.supports_network_strategy() {
            let has_network_strategy = match outbound {
                Outbound::Direct(o) => o.dial.network_strategy.is_some(),
                Outbound::Socks(o) => o.dial.network_strategy.is_some(),
                Outbound::Http(o) => o.dial.network_strategy.is_some(),
                Outbound::Shadowsocks(o) => o.dial.network_strategy.is_some(),
                Outbound::VMess(o) => o.dial.network_strategy.is_some(),
                Outbound::Trojan(o) => o.dial.network_strategy.is_some(),
                Outbound::WireGuard(o) => o.dial.network_strategy.is_some(),
                Outbound::Hysteria(o) => o.dial.network_strategy.is_some(),
                Outbound::Hysteria2(o) => o.dial.network_strategy.is_some(),
                Outbound::VLess(o) => o.dial.network_strategy.is_some(),
                Outbound::ShadowTls(o) => o.dial.network_strategy.is_some(),
                Outbound::Tuic(o) => o.dial.network_strategy.is_some(),
                Outbound::AnyTls(o) => o.dial.network_strategy.is_some(),
                Outbound::Tor(o) => o.dial.network_strategy.is_some(),
                Outbound::Ssh(o) => o.dial.network_strategy.is_some(),
                Outbound::Naive(o) => o.dial.network_strategy.is_some(),
                _ => false,
            };

            if has_network_strategy {
                let tag = get_outbound_tag(outbound).unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("outbound '{}' dial.network_strategy", tag),
                    min_version: "1.11".to_string(),
                    target_version: version_str.to_string(),
                });
            }
        }

        if version >= &SingBoxVersion::new(1, 14) {
            let has_domain_strategy = match outbound {
                Outbound::Direct(o) => o.dial.domain_strategy.is_some(),
                Outbound::Socks(o) => o.dial.domain_strategy.is_some(),
                Outbound::Http(o) => o.dial.domain_strategy.is_some(),
                Outbound::Shadowsocks(o) => o.dial.domain_strategy.is_some(),
                Outbound::VMess(o) => o.dial.domain_strategy.is_some(),
                Outbound::Trojan(o) => o.dial.domain_strategy.is_some(),
                Outbound::WireGuard(o) => o.dial.domain_strategy.is_some(),
                Outbound::Hysteria(o) => o.dial.domain_strategy.is_some(),
                Outbound::Hysteria2(o) => o.dial.domain_strategy.is_some(),
                Outbound::VLess(o) => o.dial.domain_strategy.is_some(),
                Outbound::ShadowTls(o) => o.dial.domain_strategy.is_some(),
                Outbound::Tuic(o) => o.dial.domain_strategy.is_some(),
                Outbound::AnyTls(o) => o.dial.domain_strategy.is_some(),
                Outbound::Tor(o) => o.dial.domain_strategy.is_some(),
                Outbound::Ssh(o) => o.dial.domain_strategy.is_some(),
                Outbound::Naive(o) => o.dial.domain_strategy.is_some(),
                _ => false,
            };

            if has_domain_strategy {
                let tag = get_outbound_tag(outbound).unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::DeprecatedFeature {
                    feature: format!("outbound '{}' dial.domain_strategy", tag),
                    deprecated_in: "1.14".to_string(),
                    target_version: version_str.to_string(),
                    suggestion: Some("use dial.domain_resolver instead".to_string()),
                });
            }
        }
    }

    /// Check inbound version compatibility.
    fn check_inbound_version_compatibility(
        &self,
        inbound: &Inbound,
        version: &SingBoxVersion,
        version_str: &str,
        result: &mut ValidationResult,
    ) {
        match inbound {
            Inbound::Cloudflared(_) if version < &SingBoxVersion::new(1, 14) => {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "cloudflared inbound".to_string(),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            Inbound::Hysteria(h) => {
                let tag = h.tag.clone().unwrap_or_else(|| "<unnamed>".to_string());
                if h.quic.is_set() && version < &SingBoxVersion::new(1, 14) {
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!("hysteria inbound '{}' QUIC tuning fields", tag),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                }
                if version >= &SingBoxVersion::new(1, 14)
                    && (h.recv_window_conn.is_some()
                        || h.recv_window.is_some()
                        || h.recv_window_client.is_some()
                        || h.max_conn_client.is_some()
                        || h.disable_mtu_discovery)
                {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: format!("hysteria inbound '{}' legacy QUIC tuning", tag),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "use stream_receive_window, connection_receive_window, disable_path_mtu_discovery"
                                .to_string(),
                        ),
                    });
                }
            }
            Inbound::Hysteria2(inbound)
                if inbound.bbr_profile.is_some() && version < &SingBoxVersion::new(1, 14) =>
            {
                let tag = inbound
                    .tag
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("hysteria2 inbound '{}' bbr_profile", tag),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            Inbound::Hysteria2(inbound)
                if inbound.quic.is_set() && version < &SingBoxVersion::new(1, 14) =>
            {
                let tag = inbound
                    .tag
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("hysteria2 inbound '{}' QUIC tuning fields", tag),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            Inbound::Tuic(inbound)
                if inbound.quic.is_set() && version < &SingBoxVersion::new(1, 14) =>
            {
                let tag = inbound
                    .tag
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("tuic inbound '{}' QUIC tuning fields", tag),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            Inbound::Tun(inbound)
                if (!inbound.include_mac_address.is_empty()
                    || !inbound.exclude_mac_address.is_empty())
                    && version < &SingBoxVersion::new(1, 14) =>
            {
                let tag = inbound
                    .tag
                    .clone()
                    .unwrap_or_else(|| "<unnamed>".to_string());
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("tun inbound '{}' mac address filters", tag),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            _ => {}
        }

        let tls = match inbound {
            Inbound::Trojan(i) => i.tls.as_ref(),
            Inbound::Naive(i) => i.tls.as_ref(),
            Inbound::Hysteria(i) => i.tls.as_ref(),
            Inbound::Tuic(i) => i.tls.as_ref(),
            Inbound::Hysteria2(i) => i.tls.as_ref(),
            Inbound::VLess(i) => i.tls.as_ref(),
            Inbound::AnyTls(i) => i.tls.as_ref(),
            _ => None,
        };

        if let Some(tls) = tls {
            if tls.certificate_provider.is_some() && version < &SingBoxVersion::new(1, 14) {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: "tls.certificate_provider".to_string(),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }

            if version >= &SingBoxVersion::new(1, 14) && tls.acme.is_some() {
                result.add_warning(ConfigWarning::DeprecatedFeature {
                    feature: "tls.acme".to_string(),
                    deprecated_in: "1.14".to_string(),
                    target_version: version_str.to_string(),
                    suggestion: Some(
                        "use tls.certificate_provider or certificate_providers instead".to_string(),
                    ),
                });
            }
        }
    }

    /// Check TLS version compatibility for outbound TLS (1.14 engine/spoof fields).
    fn check_outbound_tls_114(
        &self,
        tls: &crate::config::shared::OutboundTlsConfig,
        version: &SingBoxVersion,
        version_str: &str,
        context: &str,
        result: &mut ValidationResult,
    ) {
        if version < &SingBoxVersion::new(1, 14) {
            if tls.engine.is_some() {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("{}: tls.engine", context),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            if tls.spoof.is_some() {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("{}: tls.spoof", context),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
            if tls.spoof_method.is_some() {
                result.add_warning(ConfigWarning::UnsupportedFeature {
                    feature: format!("{}: tls.spoof_method", context),
                    min_version: "1.14".to_string(),
                    target_version: version_str.to_string(),
                });
            }
        }
    }

    /// Check DNS version compatibility.
    fn check_dns_version_compatibility(
        &self,
        dns: &crate::config::dns::Dns,
        version: &SingBoxVersion,
        version_str: &str,
        result: &mut ValidationResult,
    ) {
        let is_v14_or_newer = version >= &SingBoxVersion::new(1, 14);

        // Check for legacy DNS server format (deprecated in 1.12)
        for server in &dns.servers {
            if matches!(server, DnsServer::Legacy(_)) && !version.supports_legacy_dns() {
                result.add_warning(ConfigWarning::DeprecatedFeature {
                    feature: "legacy DNS server format".to_string(),
                    deprecated_in: "1.12".to_string(),
                    target_version: version_str.to_string(),
                    suggestion: Some(
                        "use typed DNS servers (local, udp, tcp, tls, https, etc.)".to_string(),
                    ),
                });
                break; // Only warn once
            }
        }

        // Check for deprecated fakeip in DNS config (deprecated in 1.12)
        if dns.fakeip.is_some() && !version.supports_legacy_fakeip() {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "dns.fakeip".to_string(),
                deprecated_in: "1.12".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("use fakeip DNS server type instead".to_string()),
            });
        }

        if dns.optimistic.is_some() && version < &SingBoxVersion::new(1, 14) {
            result.add_warning(ConfigWarning::UnsupportedFeature {
                feature: "dns.optimistic".to_string(),
                min_version: "1.14".to_string(),
                target_version: version_str.to_string(),
            });
        }

        // Tailscale DNS server accept_search_domain (since 1.14.0-alpha.15)
        if version < &SingBoxVersion::new(1, 14) {
            for server in &dns.servers {
                if let DnsServer::Tailscale(ts) = server
                    && ts.accept_search_domain
                {
                    result.add_warning(ConfigWarning::UnsupportedFeature {
                        feature: format!(
                            "tailscale DNS server '{}' accept_search_domain",
                            ts.tag
                        ),
                        min_version: "1.14".to_string(),
                        target_version: version_str.to_string(),
                    });
                    break;
                }
            }
        }

        if is_v14_or_newer && dns.independent_cache {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "dns.independent_cache".to_string(),
                deprecated_in: "1.14".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("remove this field".to_string()),
            });
        }

        if is_v14_or_newer
            && let Some(experimental) = &self.experimental
            && let Some(cache_file) = &experimental.cache_file
            && cache_file.store_rdrc
        {
            result.add_warning(ConfigWarning::DeprecatedFeature {
                feature: "experimental.cache_file.store_rdrc".to_string(),
                deprecated_in: "1.14".to_string(),
                target_version: version_str.to_string(),
                suggestion: Some("use experimental.cache_file.store_dns instead".to_string()),
            });
        }

        // Check DNS rules for deprecated outbound field
        let mut seen_top_level_evaluate = false;
        for (index, rule) in dns.rules.iter().enumerate() {
            let has_deprecated_outbound = match rule {
                DnsRule::Default(r) => !r.outbound.is_empty(),
                DnsRule::Logical(_) => false,
            };

            if has_deprecated_outbound && !version.supports_dns_rule_outbound() {
                result.add_warning(ConfigWarning::DeprecatedFeature {
                    feature: "dns rule outbound field".to_string(),
                    deprecated_in: "1.12".to_string(),
                    target_version: version_str.to_string(),
                    suggestion: Some("use action.route.server instead".to_string()),
                });
                break; // Only warn once
            }

            if is_v14_or_newer {
                self.check_dns_rule_114_compatibility(
                    rule,
                    index,
                    seen_top_level_evaluate,
                    false,
                    result,
                );
                self.check_dns_rule_114_deprecations(rule, version_str, result);
            }

            if dns_rule_action_is_evaluate(rule) {
                seen_top_level_evaluate = true;
            }
        }

        if is_v14_or_newer {
            let mut referenced_rule_sets = HashSet::new();
            for rule in &dns.rules {
                collect_dns_rule_set_refs(rule, &mut referenced_rule_sets);
            }

            let referenced_rule_set_has_query_type = self.route.as_ref().is_some_and(|route| {
                route.rule_set.iter().any(|rule_set| {
                    referenced_rule_sets.contains(&get_rule_set_tag(rule_set))
                        && rule_set_contains_query_type(rule_set)
                })
            });

            let has_ip_version_or_query_type =
                dns.rules.iter().any(dns_rule_has_ip_version_or_query_type)
                    || referenced_rule_set_has_query_type;

            if has_ip_version_or_query_type {
                for (index, rule) in dns.rules.iter().enumerate() {
                    self.check_dns_rule_114_incompatibilities(rule, index, result);
                }
            }
        }
    }

    /// Check 1.14 DNS rule semantics like evaluate/respond ordering and response matching.
    fn check_dns_rule_114_compatibility(
        &self,
        rule: &DnsRule,
        rule_index: usize,
        has_preceding_top_level_evaluate: bool,
        inside_logical: bool,
        result: &mut ValidationResult,
    ) {
        match rule {
            DnsRule::Default(rule) => {
                let has_response_fields = dns_rule_has_response_fields(rule);

                if matches!(
                    &rule.action,
                    crate::config::dns::DnsRuleAction::Tagged(
                        crate::config::dns::TaggedDnsRuleAction::Evaluate(_)
                    )
                ) && inside_logical
                {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "'evaluate' is only allowed on top-level DNS rules".to_string(),
                    });
                }

                if has_response_fields && !rule.match_response {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "response match fields require 'match_response' to be set to true"
                            .to_string(),
                    });
                }

                if (rule.match_response || has_response_fields) && !has_preceding_top_level_evaluate
                {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "response matching requires a preceding top-level 'evaluate' rule"
                            .to_string(),
                    });
                }

                if matches!(
                    &rule.action,
                    crate::config::dns::DnsRuleAction::Tagged(
                        crate::config::dns::TaggedDnsRuleAction::Respond
                    )
                ) && !has_preceding_top_level_evaluate
                {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "'respond' requires a preceding top-level 'evaluate' rule"
                            .to_string(),
                    });
                }
            }
            DnsRule::Logical(logical) => {
                if matches!(
                    &logical.action,
                    crate::config::dns::DnsRuleAction::Tagged(
                        crate::config::dns::TaggedDnsRuleAction::Respond
                    )
                ) && !has_preceding_top_level_evaluate
                {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "'respond' requires a preceding top-level 'evaluate' rule"
                            .to_string(),
                    });
                }

                for nested_rule in &logical.rules {
                    self.check_dns_rule_114_compatibility(
                        nested_rule,
                        rule_index,
                        has_preceding_top_level_evaluate,
                        true,
                        result,
                    );
                }
            }
        }
    }

    /// Check 1.14 DNS incompatibilities involving ip_version/query_type and legacy fields.
    fn check_dns_rule_114_deprecations(
        &self,
        rule: &DnsRule,
        version_str: &str,
        result: &mut ValidationResult,
    ) {
        match rule {
            DnsRule::Default(rule) => {
                if !rule.ip_cidr.is_empty() && !rule.match_response {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: "dns rule ip_cidr".to_string(),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "use 'evaluate' with 'match_response' instead".to_string(),
                        ),
                    });
                }

                if rule.ip_is_private && !rule.match_response {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: "dns rule ip_is_private".to_string(),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "use 'evaluate' with 'match_response' instead".to_string(),
                        ),
                    });
                }

                if rule.rule_set_ip_cidr_accept_empty {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: "dns rule rule_set_ip_cidr_accept_empty".to_string(),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "use 'evaluate' with 'match_response' instead".to_string(),
                        ),
                    });
                }

                if dns_rule_action_uses_legacy_strategy(&rule.action) {
                    result.add_warning(ConfigWarning::DeprecatedFeature {
                        feature: "dns rule action strategy".to_string(),
                        deprecated_in: "1.14".to_string(),
                        target_version: version_str.to_string(),
                        suggestion: Some(
                            "remove legacy strategy from the DNS rule action".to_string(),
                        ),
                    });
                }
            }
            DnsRule::Logical(logical) => {
                for nested_rule in &logical.rules {
                    self.check_dns_rule_114_deprecations(
                        nested_rule,
                        version_str,
                        result,
                    );
                }
            }
        }
    }

    /// Check 1.14 DNS incompatibilities involving ip_version/query_type and legacy fields.
    fn check_dns_rule_114_incompatibilities(
        &self,
        rule: &DnsRule,
        rule_index: usize,
        result: &mut ValidationResult,
    ) {
        match rule {
            DnsRule::Default(rule) => {
                if dns_rule_uses_legacy_address_filters(rule) {
                    result.add_error(ConfigError::InvalidDnsRule {
                        rule_index,
                        message: "'ip_version' or 'query_type' cannot be combined with legacy address filter fields, legacy DNS rule action 'strategy', or 'rule_set_ip_cidr_accept_empty' in sing-box 1.14".to_string(),
                    });
                }
            }
            DnsRule::Logical(logical) => {
                for nested_rule in &logical.rules {
                    self.check_dns_rule_114_incompatibilities(
                        nested_rule,
                        rule_index,
                        result,
                    );
                }
            }
        }
    }

    /// Check for conflicting fields that may cause unexpected behavior.
    fn check_field_conflicts(&self, result: &mut ValidationResult) {
        // Check outbound conflicts
        for outbound in &self.outbounds {
            match outbound {
                Outbound::Hysteria(h) => {
                    // Check server_port vs server_ports conflict
                    if h.server_port.is_some() && !h.server_ports.is_empty() {
                        result.add_warning(ConfigWarning::HysteriaServerPortConflict {
                            outbound: h.tag.clone().unwrap_or_else(|| "<unnamed>".to_string()),
                        });
                    }
                    // Check dial fields bind vs network_strategy conflict
                    if h.dial.network_strategy.is_some()
                        && (h.dial.bind_interface.is_some()
                            || h.dial.inet4_bind_address.is_some()
                            || h.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: h.tag.clone(),
                        });
                    }
                }
                Outbound::Hysteria2(h2) => {
                    // Check server_port vs server_ports conflict
                    if h2.server_port.is_some() && !h2.server_ports.is_empty() {
                        result.add_warning(ConfigWarning::Hysteria2ServerPortConflict {
                            outbound: h2.tag.clone().unwrap_or_else(|| "<unnamed>".to_string()),
                        });
                    }
                    // Check dial fields bind vs network_strategy conflict
                    if h2.dial.network_strategy.is_some()
                        && (h2.dial.bind_interface.is_some()
                            || h2.dial.inet4_bind_address.is_some()
                            || h2.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: h2.tag.clone(),
                        });
                    }
                }
                // Check dial fields for other outbound types that have them
                Outbound::Direct(d) => {
                    if d.dial.network_strategy.is_some()
                        && (d.dial.bind_interface.is_some()
                            || d.dial.inet4_bind_address.is_some()
                            || d.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: d.tag.clone(),
                        });
                    }
                }
                Outbound::Socks(s) => {
                    if s.dial.network_strategy.is_some()
                        && (s.dial.bind_interface.is_some()
                            || s.dial.inet4_bind_address.is_some()
                            || s.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: s.tag.clone(),
                        });
                    }
                }
                Outbound::Http(h) => {
                    if h.dial.network_strategy.is_some()
                        && (h.dial.bind_interface.is_some()
                            || h.dial.inet4_bind_address.is_some()
                            || h.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: h.tag.clone(),
                        });
                    }
                }
                Outbound::Shadowsocks(ss) => {
                    if ss.dial.network_strategy.is_some()
                        && (ss.dial.bind_interface.is_some()
                            || ss.dial.inet4_bind_address.is_some()
                            || ss.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: ss.tag.clone(),
                        });
                    }
                }
                Outbound::VMess(v) => {
                    if v.dial.network_strategy.is_some()
                        && (v.dial.bind_interface.is_some()
                            || v.dial.inet4_bind_address.is_some()
                            || v.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: v.tag.clone(),
                        });
                    }
                }
                Outbound::Trojan(t) => {
                    if t.dial.network_strategy.is_some()
                        && (t.dial.bind_interface.is_some()
                            || t.dial.inet4_bind_address.is_some()
                            || t.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: t.tag.clone(),
                        });
                    }
                }
                Outbound::WireGuard(w) => {
                    if w.dial.network_strategy.is_some()
                        && (w.dial.bind_interface.is_some()
                            || w.dial.inet4_bind_address.is_some()
                            || w.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: w.tag.clone(),
                        });
                    }
                }
                Outbound::ShadowTls(st) => {
                    if st.dial.network_strategy.is_some()
                        && (st.dial.bind_interface.is_some()
                            || st.dial.inet4_bind_address.is_some()
                            || st.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: st.tag.clone(),
                        });
                    }
                }
                Outbound::Tuic(t) => {
                    if t.dial.network_strategy.is_some()
                        && (t.dial.bind_interface.is_some()
                            || t.dial.inet4_bind_address.is_some()
                            || t.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: t.tag.clone(),
                        });
                    }
                }
                Outbound::VLess(v) => {
                    if v.dial.network_strategy.is_some()
                        && (v.dial.bind_interface.is_some()
                            || v.dial.inet4_bind_address.is_some()
                            || v.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: v.tag.clone(),
                        });
                    }
                }
                Outbound::Ssh(s) => {
                    if s.dial.network_strategy.is_some()
                        && (s.dial.bind_interface.is_some()
                            || s.dial.inet4_bind_address.is_some()
                            || s.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: s.tag.clone(),
                        });
                    }
                }
                Outbound::AnyTls(a) => {
                    if a.dial.network_strategy.is_some()
                        && (a.dial.bind_interface.is_some()
                            || a.dial.inet4_bind_address.is_some()
                            || a.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: a.tag.clone(),
                        });
                    }
                }
                Outbound::Tor(t) => {
                    if t.dial.network_strategy.is_some()
                        && (t.dial.bind_interface.is_some()
                            || t.dial.inet4_bind_address.is_some()
                            || t.dial.inet6_bind_address.is_some())
                    {
                        result.add_warning(ConfigWarning::DialFieldsBindStrategyConflict {
                            outbound: t.tag.clone(),
                        });
                    }
                }
                // Selector, UrlTest, Block, Dns don't have dial fields with these conflicts
                _ => {}
            }
        }

        // Check route conflicts
        if let Some(route) = &self.route
            && route.default_interface.is_some()
            && route.default_network_strategy.is_some()
        {
            result.add_warning(ConfigWarning::RouteInterfaceStrategyConflict);
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
            match &r.action {
                crate::config::dns::DnsRuleAction::Legacy(legacy) if !legacy.server.is_empty() => {
                    return Some(legacy.server.clone());
                }
                crate::config::dns::DnsRuleAction::Tagged(
                    crate::config::dns::TaggedDnsRuleAction::Route(route),
                ) if !route.server.is_empty() => {
                    return Some(route.server.clone());
                }
                _ => {}
            }
            // Fall back to legacy outbound field (first item)
            r.outbound.first().cloned()
        }
        DnsRule::Logical(r) => {
            match &r.action {
                crate::config::dns::DnsRuleAction::Legacy(legacy) if !legacy.server.is_empty() => {
                    return Some(legacy.server.clone());
                }
                crate::config::dns::DnsRuleAction::Tagged(
                    crate::config::dns::TaggedDnsRuleAction::Route(route),
                ) if !route.server.is_empty() => {
                    return Some(route.server.clone());
                }
                _ => {}
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
    use crate::config::dns::{
        DefaultDnsRule, Dns, DnsRuleAction, LegacyRouteAction, LocalDnsServer, Strategy,
        TaggedDnsRuleAction, UdpDnsServer,
    };
    use crate::config::experimental::{CacheFile, Experimental};
    use crate::config::inbound::TrojanInbound;
    use crate::config::outbound::{BlockOutbound, DirectOutbound, SelectorOutbound, SocksOutbound};
    use crate::config::route::{InlineRuleSet, LocalRuleSet, Route, RouteAction};
    use crate::config::shared::{AcmeConfig, DialFields, InboundTlsConfig};

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
    fn test_selector_default_outbound_not_found() {
        let mut selector = SelectorOutbound::new("select", vec!["direct".to_string()]);
        selector.default = Some("nonexistent".to_string());

        let config = SingBoxConfig {
            outbounds: vec![
                Outbound::Direct(DirectOutbound::new("direct")),
                Outbound::Selector(selector),
            ],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_errors());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ConfigError::SelectorDefaultOutboundNotFound { selector, outbound }
                if selector == "select" && outbound == "nonexistent"
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
                    ..Default::default()
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
                    ..Default::default()
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
                        ..Default::default()
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
    fn test_hysteria2_server_port_conflict_warning() {
        use crate::config::outbound::Hysteria2Outbound;

        let config = SingBoxConfig {
            outbounds: vec![Outbound::Hysteria2(Hysteria2Outbound {
                tag: Some("hy2".to_string()),
                server: Some("example.com".to_string()),
                server_port: Some(443),
                server_ports: vec!["20000:40000".to_string()],
                ..Default::default()
            })],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::Hysteria2ServerPortConflict { outbound } if outbound == "hy2"
        )));
    }

    #[test]
    fn test_hysteria_server_port_conflict_warning() {
        use crate::config::outbound::HysteriaOutbound;

        let config = SingBoxConfig {
            outbounds: vec![Outbound::Hysteria(HysteriaOutbound {
                tag: Some("hy".to_string()),
                server: Some("example.com".to_string()),
                server_port: Some(443),
                server_ports: vec!["20000:30000".to_string()],
                ..Default::default()
            })],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::HysteriaServerPortConflict { outbound } if outbound == "hy"
        )));
    }

    #[test]
    fn test_route_interface_strategy_conflict_warning() {
        use crate::config::route::NetworkStrategy as RouteNetworkStrategy;

        let config = SingBoxConfig {
            route: Some(Route {
                default_interface: Some("eth0".to_string()),
                default_network_strategy: Some(RouteNetworkStrategy::Fallback),
                ..Default::default()
            }),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_warnings());
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::RouteInterfaceStrategyConflict))
        );
    }

    #[test]
    fn test_dial_fields_bind_strategy_conflict_warning() {
        use crate::config::shared::NetworkStrategy;

        let mut outbound = SocksOutbound::new("socks", "127.0.0.1", 1080);
        outbound.dial = DialFields {
            bind_interface: Some("eth0".to_string()),
            network_strategy: Some(NetworkStrategy::Hybrid),
            ..Default::default()
        };

        let config = SingBoxConfig {
            outbounds: vec![Outbound::Socks(outbound)],
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::DialFieldsBindStrategyConflict { outbound } if outbound == &Some("socks".to_string())
        )));
    }

    #[test]
    fn test_no_warning_when_no_conflict() {
        use crate::config::outbound::Hysteria2Outbound;

        // Only server_ports, no server_port
        let config = SingBoxConfig {
            outbounds: vec![Outbound::Hysteria2(Hysteria2Outbound {
                tag: Some("hy2".to_string()),
                server: Some("example.com".to_string()),
                server_ports: vec!["20000-40000".to_string()],
                ..Default::default()
            })],
            ..Default::default()
        };

        let result = config.validate();
        assert!(!result.has_warnings());
    }

    #[test]
    fn test_warning_display_messages() {
        let warning = ConfigWarning::Hysteria2ServerPortConflict {
            outbound: "hy2".to_string(),
        };
        assert!(warning.to_string().contains("server_port"));
        assert!(warning.to_string().contains("server_ports"));
        assert!(warning.to_string().contains("ignored"));

        let warning = ConfigWarning::RouteInterfaceStrategyConflict;
        assert!(warning.to_string().contains("default_interface"));
        assert!(warning.to_string().contains("default_network_strategy"));

        let warning = ConfigWarning::DialFieldsBindStrategyConflict {
            outbound: Some("proxy".to_string()),
        };
        assert!(warning.to_string().contains("network_strategy"));
        assert!(warning.to_string().contains("bind_interface"));
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
                        ..Default::default()
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

    // ========================================================================
    // Version-specific Validation Tests
    // ========================================================================

    #[test]
    fn test_version_warning_services_in_old_version() {
        use crate::config::service::{ResolvedService, Service};

        let config = SingBoxConfig {
            services: vec![Service::Resolved(Box::new(ResolvedService::new()))],
            ..Default::default()
        };

        // Services require 1.12+, should warn when targeting 1.10 or 1.11
        let result = config.validate_for_version(&SingBoxVersion::new(1, 10));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature == "services" && min_version == "1.12"
        )));

        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(result.has_warnings());

        // Should not warn when targeting 1.12+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 12));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. } if feature == "services"
        )));
    }

    #[test]
    fn test_version_warning_endpoints_in_old_version() {
        use crate::config::endpoint::{Endpoint, WireGuardEndpoint};

        let config = SingBoxConfig {
            endpoints: vec![Endpoint::WireGuard(WireGuardEndpoint::new(
                "wg",
                "private_key==",
                vec!["10.0.0.1/24".to_string()],
            ))],
            ..Default::default()
        };

        // Endpoints require 1.11+, should warn when targeting 1.10
        let result = config.validate_for_version(&SingBoxVersion::new(1, 10));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature == "endpoints" && min_version == "1.11"
        )));

        // Should not warn when targeting 1.11+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. } if feature == "endpoints"
        )));
    }

    #[test]
    fn test_version_warning_certificate_in_old_version() {
        use crate::config::certificate::Certificate;

        let config = SingBoxConfig {
            certificate: Some(Certificate::default()),
            ..Default::default()
        };

        // Certificate requires 1.12+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature == "certificate" && min_version == "1.12"
        )));

        // Should not warn when targeting 1.12+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 12));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. } if feature == "certificate"
        )));
    }

    #[test]
    fn test_version_warning_hysteria2_port_hopping_in_old_version() {
        use crate::config::outbound::Hysteria2Outbound;

        let config = SingBoxConfig {
            outbounds: vec![Outbound::Hysteria2(Hysteria2Outbound {
                tag: Some("hy2".to_string()),
                server: Some("example.com".to_string()),
                server_ports: vec!["20000:40000".to_string()],
                ..Default::default()
            })],
            ..Default::default()
        };

        // Hysteria2 server_ports requires 1.11+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 10));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature.contains("hysteria2") && feature.contains("server_ports") && min_version == "1.11"
        )));

        // Should not warn when targeting 1.11+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. } if feature.contains("hysteria2") && feature.contains("server_ports")
        )));
    }

    #[test]
    fn test_version_warning_hysteria_port_hopping_in_old_version() {
        use crate::config::outbound::HysteriaOutbound;

        let config = SingBoxConfig {
            outbounds: vec![Outbound::Hysteria(HysteriaOutbound {
                tag: Some("hy".to_string()),
                server: Some("example.com".to_string()),
                server_ports: vec!["20000:30000".to_string()],
                ..Default::default()
            })],
            ..Default::default()
        };

        // Hysteria server_ports requires 1.12+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature.contains("hysteria") && !feature.contains("hysteria2") && feature.contains("server_ports") && min_version == "1.12"
        )));

        // Should not warn when targeting 1.12+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 12));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. }
            if feature.contains("hysteria") && !feature.contains("hysteria2") && feature.contains("server_ports")
        )));
    }

    #[test]
    fn test_version_warning_deprecated_geosite() {
        let config = SingBoxConfig {
            route: Some(
                Route::new().add_rule(RouteRule::new().match_geosite(vec!["cn".to_string()])),
            ),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        // geosite is deprecated/removed in 1.12
        let result = config.validate_for_version(&SingBoxVersion::new(1, 12));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, suggestion, .. }
            if feature.contains("geosite") && deprecated_in == "1.12" && suggestion.is_some()
        )));

        // Should not warn when targeting 1.11 (still supported)
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::DeprecatedFeature { feature, .. } if feature.contains("geosite")
        )));
    }

    #[test]
    fn test_version_warning_deprecated_geoip() {
        let config = SingBoxConfig {
            route: Some(
                Route::new().add_rule(RouteRule::new().match_geoip(vec!["cn".to_string()])),
            ),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        // geoip is deprecated/removed in 1.12
        let result = config.validate_for_version(&SingBoxVersion::new(1, 12));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature.contains("geoip") && deprecated_in == "1.12"
        )));

        // Should not warn when targeting 1.11 (still supported)
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::DeprecatedFeature { feature, .. } if feature.contains("geoip")
        )));
    }

    #[test]
    fn test_version_warning_network_strategy_in_old_version() {
        use crate::config::route::NetworkStrategy as RouteNetworkStrategy;

        let config = SingBoxConfig {
            route: Some(Route {
                default_network_strategy: Some(RouteNetworkStrategy::Fallback),
                ..Default::default()
            }),
            outbounds: vec![Outbound::Direct(DirectOutbound::new("direct"))],
            ..Default::default()
        };

        // network_strategy requires 1.11+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 10));
        assert!(result.has_warnings());
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, min_version, .. }
            if feature.contains("network_strategy") && min_version == "1.11"
        )));

        // Should not warn when targeting 1.11+
        let result = config.validate_for_version(&SingBoxVersion::new(1, 11));
        assert!(!result.warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::UnsupportedFeature { feature, .. } if feature.contains("default_network_strategy")
        )));
    }

    #[test]
    fn test_version_warning_display_unsupported() {
        let warning = ConfigWarning::UnsupportedFeature {
            feature: "services".to_string(),
            min_version: "1.12".to_string(),
            target_version: "1.10".to_string(),
        };
        let msg = warning.to_string();
        assert!(msg.contains("services"));
        assert!(msg.contains("1.12"));
        assert!(msg.contains("1.10"));
        assert!(msg.contains("requires"));
    }

    #[test]
    fn test_version_warning_display_deprecated() {
        let warning = ConfigWarning::DeprecatedFeature {
            feature: "geosite".to_string(),
            deprecated_in: "1.12".to_string(),
            target_version: "1.13".to_string(),
            suggestion: Some("use rule_set instead".to_string()),
        };
        let msg = warning.to_string();
        assert!(msg.contains("geosite"));
        assert!(msg.contains("1.12"));
        assert!(msg.contains("1.13"));
        assert!(msg.contains("rule_set"));

        // Without suggestion
        let warning = ConfigWarning::DeprecatedFeature {
            feature: "geosite".to_string(),
            deprecated_in: "1.12".to_string(),
            target_version: "1.13".to_string(),
            suggestion: None,
        };
        let msg = warning.to_string();
        assert!(msg.contains("deprecated"));
        assert!(!msg.contains("rule_set"));
    }

    #[test]
    fn test_validate_for_version_no_warnings_for_compatible_config() {
        // Build a config that's compatible with 1.10
        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .build();

        // Should have no version warnings for any supported version
        for minor in 10..=13 {
            let result = config.validate_for_version(&SingBoxVersion::new(1, minor));
            assert!(
                !result.has_warnings(),
                "Unexpected warnings for version 1.{}: {:?}",
                minor,
                result.warnings
            );
        }
    }

    #[test]
    fn test_version_warning_dns_114_deprecations() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                independent_cache: true,
                rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                    ip_cidr: vec!["1.1.1.0/24".to_string()],
                    rule_set_ip_cidr_accept_empty: true,
                    action: DnsRuleAction::Tagged(TaggedDnsRuleAction::Route(
                        crate::config::dns::RouteAction {
                            server: "local".to_string(),
                            strategy: Some(Strategy::PreferIpv4),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }))],
                ..Default::default()
            }),
            experimental: Some(Experimental {
                cache_file: Some(CacheFile {
                    enabled: true,
                    store_rdrc: true,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "dns.independent_cache" && deprecated_in == "1.14"
        )));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "experimental.cache_file.store_rdrc" && deprecated_in == "1.14"
        )));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "dns rule action strategy" && deprecated_in == "1.14"
        )));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "dns rule ip_cidr" && deprecated_in == "1.14"
        )));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "dns rule rule_set_ip_cidr_accept_empty" && deprecated_in == "1.14"
        )));
    }

    #[test]
    fn test_version_warning_tls_acme_deprecated_in_114() {
        let config = SingBoxConfig {
            inbounds: vec![Inbound::Trojan(TrojanInbound {
                tag: Some("trojan-in".to_string()),
                tls: Some(InboundTlsConfig {
                    enabled: true,
                    acme: Some(AcmeConfig {
                        domain: vec!["example.com".to_string()],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })],
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            ConfigWarning::DeprecatedFeature { feature, deprecated_in, .. }
            if feature == "tls.acme" && deprecated_in == "1.14"
        )));
    }

    #[test]
    fn test_validate_dns_response_matching_requires_preceding_evaluate() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                    match_response: true,
                    response_answer: vec!["example.com. 60 IN A 1.1.1.1".to_string()],
                    ..Default::default()
                }))],
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.errors.iter().any(|error| matches!(
            error,
            ConfigError::InvalidDnsRule { message, .. }
            if message.contains("preceding top-level 'evaluate' rule")
        )));
    }

    #[test]
    fn test_validate_dns_respond_requires_preceding_evaluate() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                    action: DnsRuleAction::Tagged(TaggedDnsRuleAction::Respond),
                    ..Default::default()
                }))],
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.errors.iter().any(|error| matches!(
            error,
            ConfigError::InvalidDnsRule { message, .. }
            if message.contains("'respond' requires a preceding top-level 'evaluate' rule")
        )));
    }

    #[test]
    fn test_validate_dns_evaluate_not_allowed_in_logical_subrules() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                rules: vec![DnsRule::Logical(crate::config::dns::LogicalDnsRule {
                    r#type: "logical".to_string(),
                    mode: crate::config::dns::LogicalMode::And,
                    rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                        action: DnsRuleAction::Tagged(TaggedDnsRuleAction::Evaluate(
                            crate::config::dns::EvaluateAction {
                                server: "dns".to_string(),
                                ..Default::default()
                            },
                        )),
                        ..Default::default()
                    }))],
                    action: DnsRuleAction::Legacy(LegacyRouteAction {
                        server: "dns".to_string(),
                        strategy: None,
                        disable_cache: false,
                        rewrite_ttl: None,
                        client_subnet: None,
                    }),
                })],
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.errors.iter().any(|error| matches!(
            error,
            ConfigError::InvalidDnsRule { message, .. }
            if message.contains("'evaluate' is only allowed on top-level DNS rules")
        )));
    }

    #[test]
    fn test_validate_dns_ip_version_incompatible_with_legacy_fields() {
        let config = SingBoxConfig {
            dns: Some(Dns {
                rules: vec![DnsRule::Default(Box::new(DefaultDnsRule {
                    ip_version: Some(4),
                    ip_cidr: vec!["1.1.1.0/24".to_string()],
                    ..Default::default()
                }))],
                ..Default::default()
            }),
            ..Default::default()
        };

        let result = config.validate_for_version(&SingBoxVersion::new(1, 14));
        assert!(result.errors.iter().any(|error| matches!(
            error,
            ConfigError::InvalidDnsRule { message, .. }
            if message.contains("'ip_version' or 'query_type' cannot be combined")
        )));
    }
}

//! Sing-box version handling and feature detection.
//!
//! This module provides version parsing and feature detection for sing-box configurations.
//! It allows the generator to validate configurations against specific sing-box versions
//! and warn about unsupported or deprecated features.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ============================================================================
// Version Constants
// ============================================================================

/// Minimum supported sing-box version (last three major versions)
pub const MIN_SUPPORTED_VERSION: (u32, u32) = (1, 10);

/// Latest supported sing-box version
pub const LATEST_VERSION: (u32, u32) = (1, 13);

// ============================================================================
// SingBoxVersion Type
// ============================================================================

/// Represents a sing-box version for feature detection.
///
/// Versions are parsed from strings like "1.13" or "1.13.0".
/// The patch version is optional and not used for feature detection.
#[derive(Clone, Debug)]
pub struct SingBoxVersion {
    /// Major version (always 1 for sing-box)
    pub major: u32,
    /// Minor version (determines feature availability)
    pub minor: u32,
    /// Patch version (optional, not used for feature detection)
    pub patch: Option<u32>,
}

impl SingBoxVersion {
    /// Create a new version with major and minor components.
    pub fn new(major: u32, minor: u32) -> Self {
        Self {
            major,
            minor,
            patch: None,
        }
    }

    /// Create a new version with major, minor, and patch components.
    pub fn with_patch(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch: Some(patch),
        }
    }

    /// Get the latest supported version.
    pub fn latest() -> Self {
        Self::new(LATEST_VERSION.0, LATEST_VERSION.1)
    }

    /// Get the minimum supported version.
    pub fn minimum() -> Self {
        Self::new(MIN_SUPPORTED_VERSION.0, MIN_SUPPORTED_VERSION.1)
    }

    /// Check if this version is supported (within the supported range).
    pub fn is_supported(&self) -> bool {
        self.major == 1 && self.minor >= MIN_SUPPORTED_VERSION.1 && self.minor <= LATEST_VERSION.1
    }

    /// Compare versions (ignoring patch).
    fn at_least(&self, major: u32, minor: u32) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }

    /// Compare versions (ignoring patch).
    fn below(&self, major: u32, minor: u32) -> bool {
        self.major < major || (self.major == major && self.minor < minor)
    }

    // ========================================================================
    // Feature Detection - Additions by Version
    // ========================================================================

    // --- Version 1.10 Features ---

    /// TUN auto_redirect support (since 1.10.0)
    pub fn supports_tun_auto_redirect(&self) -> bool {
        self.at_least(1, 10)
    }

    /// TUN route_address and route_exclude_address (since 1.10.0)
    pub fn supports_tun_route_address(&self) -> bool {
        self.at_least(1, 10)
    }

    /// Process path regex matching in route rules (since 1.10.0)
    pub fn supports_process_path_regex(&self) -> bool {
        self.at_least(1, 10)
    }

    /// Client field in route rules for sniffed client matching (since 1.10.0)
    pub fn supports_route_client_field(&self) -> bool {
        self.at_least(1, 10)
    }

    /// CORS access control in Clash API (since 1.10.0)
    pub fn supports_clash_api_cors(&self) -> bool {
        self.at_least(1, 10)
    }

    // --- Version 1.11 Features ---

    /// Endpoints section (WireGuard endpoint) (since 1.11.0)
    pub fn supports_endpoints(&self) -> bool {
        self.at_least(1, 11)
    }

    /// Network strategy in route configuration (since 1.11.0)
    pub fn supports_network_strategy(&self) -> bool {
        self.at_least(1, 11)
    }

    /// Network type matching in route rules (since 1.11.0)
    pub fn supports_route_network_type(&self) -> bool {
        self.at_least(1, 11)
    }

    /// Hysteria2 server_ports for port hopping (since 1.11.0)
    pub fn supports_hysteria2_port_hopping(&self) -> bool {
        self.at_least(1, 11)
    }

    // --- Version 1.12 Features ---

    /// Services section (since 1.12.0)
    pub fn supports_services(&self) -> bool {
        self.at_least(1, 12)
    }

    /// Certificate section (since 1.12.0)
    pub fn supports_certificate(&self) -> bool {
        self.at_least(1, 12)
    }

    /// Tailscale endpoint (since 1.12.0)
    pub fn supports_tailscale(&self) -> bool {
        self.at_least(1, 12)
    }

    /// Hysteria (v1) server_ports for port hopping (since 1.12.0)
    pub fn supports_hysteria_port_hopping(&self) -> bool {
        self.at_least(1, 12)
    }

    /// Default domain resolver in route (since 1.12.0)
    pub fn supports_default_domain_resolver(&self) -> bool {
        self.at_least(1, 12)
    }

    /// TUN loopback_address field (since 1.12.0)
    pub fn supports_tun_loopback_address(&self) -> bool {
        self.at_least(1, 12)
    }

    /// New DNS server types (local, hosts, etc.) (since 1.12.0)
    pub fn supports_new_dns_server_types(&self) -> bool {
        self.at_least(1, 12)
    }

    // --- Version 1.13 Features ---

    /// Certificate store "chrome" option (since 1.13.0)
    pub fn supports_chrome_certificate_store(&self) -> bool {
        self.at_least(1, 13)
    }

    /// ICMP network type in route rules (since 1.13.0)
    pub fn supports_icmp_network(&self) -> bool {
        self.at_least(1, 13)
    }

    /// Interface address matching in route rules (since 1.13.0)
    pub fn supports_interface_address_matching(&self) -> bool {
        self.at_least(1, 13)
    }

    /// TUN auto_redirect_reset_mark and auto_redirect_nfqueue (since 1.13.0)
    pub fn supports_tun_auto_redirect_advanced(&self) -> bool {
        self.at_least(1, 13)
    }

    /// TUN exclude_mptcp option (since 1.13.0)
    pub fn supports_tun_exclude_mptcp(&self) -> bool {
        self.at_least(1, 13)
    }

    /// Tailscale relay server and system interface options (since 1.13.0)
    pub fn supports_tailscale_advanced(&self) -> bool {
        self.at_least(1, 13)
    }

    // ========================================================================
    // Deprecation Detection
    // ========================================================================

    /// GeoIP/Geosite in route rules (deprecated in 1.8.0, removed in 1.12.0)
    pub fn supports_geoip_geosite(&self) -> bool {
        self.below(1, 12)
    }

    /// Legacy DNS server format (deprecated in 1.12.0)
    pub fn supports_legacy_dns(&self) -> bool {
        self.below(1, 12)
    }

    /// DNS rule outbound field (deprecated in 1.12.0)
    pub fn supports_dns_rule_outbound(&self) -> bool {
        self.below(1, 12)
    }

    /// FakeIP in DNS (deprecated in 1.12.0, use fakeip DNS server instead)
    pub fn supports_legacy_fakeip(&self) -> bool {
        self.below(1, 12)
    }
}

// ============================================================================
// Parsing and Display
// ============================================================================

/// Error type for version parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// The version string is empty.
    Empty,
    /// The version string has an invalid format.
    InvalidFormat(String),
    /// A version component is not a valid number.
    InvalidNumber(String),
    /// The version is below the minimum supported version.
    BelowMinimum { version: String, minimum: String },
    /// The version is above the latest supported version.
    AboveMaximum { version: String, maximum: String },
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "version string is empty"),
            Self::InvalidFormat(s) => write!(
                f,
                "invalid version format '{}': expected 'MAJOR.MINOR' or 'MAJOR.MINOR.PATCH'",
                s
            ),
            Self::InvalidNumber(s) => {
                write!(f, "invalid version component '{}': expected a number", s)
            }
            Self::BelowMinimum { version, minimum } => {
                write!(
                    f,
                    "version '{}' is below minimum supported version '{}'",
                    version, minimum
                )
            }
            Self::AboveMaximum { version, maximum } => {
                write!(
                    f,
                    "version '{}' is above latest supported version '{}'",
                    version, maximum
                )
            }
        }
    }
}

impl std::error::Error for VersionParseError {}

impl FromStr for SingBoxVersion {
    type Err = VersionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Err(VersionParseError::Empty);
        }

        let parts: Vec<&str> = s.split('.').collect();

        if parts.len() < 2 || parts.len() > 3 {
            return Err(VersionParseError::InvalidFormat(s.to_string()));
        }

        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| VersionParseError::InvalidNumber(parts[0].to_string()))?;

        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| VersionParseError::InvalidNumber(parts[1].to_string()))?;

        let patch = if parts.len() == 3 {
            Some(
                parts[2]
                    .parse::<u32>()
                    .map_err(|_| VersionParseError::InvalidNumber(parts[2].to_string()))?,
            )
        } else {
            None
        };

        let version = Self {
            major,
            minor,
            patch,
        };

        // Validate version is within supported range
        if version.below(MIN_SUPPORTED_VERSION.0, MIN_SUPPORTED_VERSION.1) {
            return Err(VersionParseError::BelowMinimum {
                version: s.to_string(),
                minimum: format!("{}.{}", MIN_SUPPORTED_VERSION.0, MIN_SUPPORTED_VERSION.1),
            });
        }

        if version.at_least(LATEST_VERSION.0, LATEST_VERSION.1 + 1) {
            return Err(VersionParseError::AboveMaximum {
                version: s.to_string(),
                maximum: format!("{}.{}", LATEST_VERSION.0, LATEST_VERSION.1),
            });
        }

        Ok(version)
    }
}

impl fmt::Display for SingBoxVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.patch {
            Some(patch) => write!(f, "{}.{}.{}", self.major, self.minor, patch),
            None => write!(f, "{}.{}", self.major, self.minor),
        }
    }
}

// ============================================================================
// Serde Support
// ============================================================================

impl Serialize for SingBoxVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SingBoxVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SingBoxVersion::from_str(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Equality and Ordering
// ============================================================================

impl PartialEq for SingBoxVersion {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major
            && self.minor == other.minor
            && self.patch.unwrap_or(0) == other.patch.unwrap_or(0)
    }
}

impl Eq for SingBoxVersion {}

impl PartialOrd for SingBoxVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SingBoxVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.major.cmp(&other.major) {
            std::cmp::Ordering::Equal => match self.minor.cmp(&other.minor) {
                std::cmp::Ordering::Equal => self.patch.unwrap_or(0).cmp(&other.patch.unwrap_or(0)),
                other => other,
            },
            other => other,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse_major_minor() {
        let v = SingBoxVersion::from_str("1.13").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 13);
        assert_eq!(v.patch, None);
    }

    #[test]
    fn test_version_parse_with_patch() {
        let v = SingBoxVersion::from_str("1.12.5").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 12);
        assert_eq!(v.patch, Some(5));
    }

    #[test]
    fn test_version_parse_with_whitespace() {
        let v = SingBoxVersion::from_str("  1.11  ").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 11);
    }

    #[test]
    fn test_version_parse_empty() {
        let err = SingBoxVersion::from_str("").unwrap_err();
        assert_eq!(err, VersionParseError::Empty);
    }

    #[test]
    fn test_version_parse_invalid_format() {
        let err = SingBoxVersion::from_str("1").unwrap_err();
        assert!(matches!(err, VersionParseError::InvalidFormat(_)));

        let err = SingBoxVersion::from_str("1.2.3.4").unwrap_err();
        assert!(matches!(err, VersionParseError::InvalidFormat(_)));
    }

    #[test]
    fn test_version_parse_invalid_number() {
        let err = SingBoxVersion::from_str("a.13").unwrap_err();
        assert!(matches!(err, VersionParseError::InvalidNumber(_)));

        let err = SingBoxVersion::from_str("1.abc").unwrap_err();
        assert!(matches!(err, VersionParseError::InvalidNumber(_)));
    }

    #[test]
    fn test_version_parse_below_minimum() {
        let err = SingBoxVersion::from_str("1.9").unwrap_err();
        assert!(matches!(err, VersionParseError::BelowMinimum { .. }));

        let err = SingBoxVersion::from_str("1.8").unwrap_err();
        assert!(matches!(err, VersionParseError::BelowMinimum { .. }));
    }

    #[test]
    fn test_version_parse_above_maximum() {
        let err = SingBoxVersion::from_str("1.99").unwrap_err();
        assert!(matches!(err, VersionParseError::AboveMaximum { .. }));

        let err = SingBoxVersion::from_str("2.0").unwrap_err();
        assert!(matches!(err, VersionParseError::AboveMaximum { .. }));
    }

    #[test]
    fn test_version_display() {
        let v = SingBoxVersion::new(1, 13);
        assert_eq!(v.to_string(), "1.13");

        let v = SingBoxVersion::with_patch(1, 12, 5);
        assert_eq!(v.to_string(), "1.12.5");
    }

    #[test]
    fn test_version_latest() {
        let v = SingBoxVersion::latest();
        assert_eq!(v.major, LATEST_VERSION.0);
        assert_eq!(v.minor, LATEST_VERSION.1);
    }

    #[test]
    fn test_version_minimum() {
        let v = SingBoxVersion::minimum();
        assert_eq!(v.major, MIN_SUPPORTED_VERSION.0);
        assert_eq!(v.minor, MIN_SUPPORTED_VERSION.1);
    }

    #[test]
    fn test_version_is_supported() {
        assert!(SingBoxVersion::new(1, 10).is_supported());
        assert!(SingBoxVersion::new(1, 11).is_supported());
        assert!(SingBoxVersion::new(1, 12).is_supported());
        assert!(SingBoxVersion::new(1, 13).is_supported());

        // Below minimum (but we can't construct these via from_str)
        assert!(!SingBoxVersion::new(1, 9).is_supported());
        assert!(!SingBoxVersion::new(1, 14).is_supported());
    }

    #[test]
    fn test_version_ordering() {
        let v110 = SingBoxVersion::new(1, 10);
        let v111 = SingBoxVersion::new(1, 11);
        let v112 = SingBoxVersion::new(1, 12);
        let v1120 = SingBoxVersion::with_patch(1, 12, 0);
        let v1125 = SingBoxVersion::with_patch(1, 12, 5);

        assert!(v110 < v111);
        assert!(v111 < v112);
        // v112 (no patch) equals v1120 (patch=0) because None.unwrap_or(0) == 0
        assert!(v112 == v1120);
        assert!(v1120 < v1125);

        // Same major.minor with patches
        let v1121 = SingBoxVersion::with_patch(1, 12, 1);
        assert!(v1120 < v1121);
        assert!(v1121 < v1125);
    }

    // ========================================================================
    // Feature Detection Tests
    // ========================================================================

    #[test]
    fn test_supports_endpoints() {
        assert!(!SingBoxVersion::new(1, 10).supports_endpoints());
        assert!(SingBoxVersion::new(1, 11).supports_endpoints());
        assert!(SingBoxVersion::new(1, 12).supports_endpoints());
        assert!(SingBoxVersion::new(1, 13).supports_endpoints());
    }

    #[test]
    fn test_supports_services() {
        assert!(!SingBoxVersion::new(1, 10).supports_services());
        assert!(!SingBoxVersion::new(1, 11).supports_services());
        assert!(SingBoxVersion::new(1, 12).supports_services());
        assert!(SingBoxVersion::new(1, 13).supports_services());
    }

    #[test]
    fn test_supports_certificate() {
        assert!(!SingBoxVersion::new(1, 10).supports_certificate());
        assert!(!SingBoxVersion::new(1, 11).supports_certificate());
        assert!(SingBoxVersion::new(1, 12).supports_certificate());
        assert!(SingBoxVersion::new(1, 13).supports_certificate());
    }

    #[test]
    fn test_supports_network_strategy() {
        assert!(!SingBoxVersion::new(1, 10).supports_network_strategy());
        assert!(SingBoxVersion::new(1, 11).supports_network_strategy());
        assert!(SingBoxVersion::new(1, 12).supports_network_strategy());
    }

    #[test]
    fn test_supports_hysteria_port_hopping() {
        assert!(!SingBoxVersion::new(1, 10).supports_hysteria_port_hopping());
        assert!(!SingBoxVersion::new(1, 11).supports_hysteria_port_hopping());
        assert!(SingBoxVersion::new(1, 12).supports_hysteria_port_hopping());
        assert!(SingBoxVersion::new(1, 13).supports_hysteria_port_hopping());
    }

    #[test]
    fn test_supports_hysteria2_port_hopping() {
        assert!(!SingBoxVersion::new(1, 10).supports_hysteria2_port_hopping());
        assert!(SingBoxVersion::new(1, 11).supports_hysteria2_port_hopping());
        assert!(SingBoxVersion::new(1, 12).supports_hysteria2_port_hopping());
    }

    #[test]
    fn test_supports_icmp_network() {
        assert!(!SingBoxVersion::new(1, 10).supports_icmp_network());
        assert!(!SingBoxVersion::new(1, 11).supports_icmp_network());
        assert!(!SingBoxVersion::new(1, 12).supports_icmp_network());
        assert!(SingBoxVersion::new(1, 13).supports_icmp_network());
    }

    #[test]
    fn test_supports_chrome_certificate_store() {
        assert!(!SingBoxVersion::new(1, 12).supports_chrome_certificate_store());
        assert!(SingBoxVersion::new(1, 13).supports_chrome_certificate_store());
    }

    // ========================================================================
    // Deprecation Detection Tests
    // ========================================================================

    #[test]
    fn test_supports_geoip_geosite() {
        assert!(SingBoxVersion::new(1, 10).supports_geoip_geosite());
        assert!(SingBoxVersion::new(1, 11).supports_geoip_geosite());
        assert!(!SingBoxVersion::new(1, 12).supports_geoip_geosite());
        assert!(!SingBoxVersion::new(1, 13).supports_geoip_geosite());
    }

    #[test]
    fn test_supports_legacy_dns() {
        assert!(SingBoxVersion::new(1, 10).supports_legacy_dns());
        assert!(SingBoxVersion::new(1, 11).supports_legacy_dns());
        assert!(!SingBoxVersion::new(1, 12).supports_legacy_dns());
        assert!(!SingBoxVersion::new(1, 13).supports_legacy_dns());
    }

    #[test]
    fn test_supports_legacy_fakeip() {
        assert!(SingBoxVersion::new(1, 10).supports_legacy_fakeip());
        assert!(SingBoxVersion::new(1, 11).supports_legacy_fakeip());
        assert!(!SingBoxVersion::new(1, 12).supports_legacy_fakeip());
    }

    // ========================================================================
    // Serde Tests
    // ========================================================================

    #[test]
    fn test_version_serde_roundtrip() {
        let v = SingBoxVersion::new(1, 13);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"1.13\"");

        let parsed: SingBoxVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_version_serde_with_patch() {
        let v = SingBoxVersion::with_patch(1, 12, 5);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"1.12.5\"");

        let parsed: SingBoxVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }

    #[test]
    fn test_version_deserialize_error() {
        let result: Result<SingBoxVersion, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());

        let result: Result<SingBoxVersion, _> = serde_json::from_str("\"1.5\"");
        assert!(result.is_err());
    }

    // ========================================================================
    // Error Display Tests
    // ========================================================================

    #[test]
    fn test_error_display() {
        let err = VersionParseError::Empty;
        assert_eq!(err.to_string(), "version string is empty");

        let err = VersionParseError::InvalidFormat("bad".to_string());
        assert!(err.to_string().contains("invalid version format"));

        let err = VersionParseError::BelowMinimum {
            version: "1.8".to_string(),
            minimum: "1.10".to_string(),
        };
        assert!(err.to_string().contains("below minimum"));

        let err = VersionParseError::AboveMaximum {
            version: "1.99".to_string(),
            maximum: "1.13".to_string(),
        };
        assert!(err.to_string().contains("above latest"));
    }
}

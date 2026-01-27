use serde::{Deserialize, Serialize};

use crate::config::shared::DialFields;
use crate::config::util::is_false;

/// NTP configuration for sing-box
///
/// Built-in NTP client service. If enabled, it will provide time for protocols
/// like TLS/Shadowsocks/VMess, which is useful for environments where time
/// synchronization is not possible.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Ntp {
    /// Enable NTP service
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// NTP server address (required when enabled)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// NTP server port (default: 123)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_port: Option<u16>,

    /// Time synchronization interval (default: "30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Dial fields for outbound connections
    #[serde(flatten)]
    pub dial: DialFields,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::shared::{DomainResolver, NetworkStrategy, NetworkType, RoutingMark};

    #[test]
    fn test_ntp_default_serializes_empty() {
        let ntp = Ntp::default();
        let json = serde_json::to_string(&ntp).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_ntp_with_basic_config() {
        let ntp = Ntp {
            enabled: true,
            server: Some("time.apple.com".to_string()),
            server_port: Some(123),
            interval: Some("30m".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&ntp).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""server":"time.apple.com""#));
        assert!(json.contains(r#""server_port":123"#));
        assert!(json.contains(r#""interval":"30m""#));
    }

    #[test]
    fn test_ntp_with_dial_fields() {
        let ntp = Ntp {
            enabled: true,
            server: Some("pool.ntp.org".to_string()),
            dial: DialFields {
                detour: Some("proxy".to_string()),
                bind_interface: Some("eth0".to_string()),
                tcp_fast_open: true,
                routing_mark: Some(RoutingMark::Number(1234)),
                network_strategy: Some(NetworkStrategy::Fallback),
                network_type: vec![NetworkType::Wifi, NetworkType::Cellular],
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&ntp).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""server":"pool.ntp.org""#));
        assert!(json.contains(r#""detour":"proxy""#));
        assert!(json.contains(r#""bind_interface":"eth0""#));
        assert!(json.contains(r#""tcp_fast_open":true"#));
        assert!(json.contains(r#""routing_mark":1234"#));
        assert!(json.contains(r#""network_strategy":"fallback""#));
        assert!(json.contains(r#""network_type":["wifi","cellular"]"#));
    }

    #[test]
    fn test_ntp_with_domain_resolver() {
        let ntp = Ntp {
            enabled: true,
            server: Some("time.google.com".to_string()),
            dial: DialFields {
                domain_resolver: Some(DomainResolver::Tag("local".to_string())),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&ntp).unwrap();
        assert!(json.contains(r#""domain_resolver":"local""#));
    }

    #[test]
    fn test_ntp_deserialization() {
        let json = r#"{"enabled": true, "server": "pool.ntp.org", "detour": "proxy"}"#;
        let ntp: Ntp = serde_json::from_str(json).unwrap();
        assert!(ntp.enabled);
        assert_eq!(ntp.server, Some("pool.ntp.org".to_string()));
        assert_eq!(ntp.dial.detour, Some("proxy".to_string()));
    }

    #[test]
    fn test_ntp_full_deserialization() {
        let json = r#"{
            "enabled": true,
            "server": "time.apple.com",
            "server_port": 123,
            "interval": "30m",
            "detour": "direct",
            "bind_interface": "en0",
            "tcp_fast_open": true,
            "routing_mark": "0x1234"
        }"#;
        let ntp: Ntp = serde_json::from_str(json).unwrap();
        assert!(ntp.enabled);
        assert_eq!(ntp.server, Some("time.apple.com".to_string()));
        assert_eq!(ntp.server_port, Some(123));
        assert_eq!(ntp.interval, Some("30m".to_string()));
        assert_eq!(ntp.dial.detour, Some("direct".to_string()));
        assert_eq!(ntp.dial.bind_interface, Some("en0".to_string()));
        assert!(ntp.dial.tcp_fast_open);
    }
}

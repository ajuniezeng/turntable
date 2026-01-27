//! Comprehensive tests for sing-box 1.13 configuration parsing.
//!
//! These tests cover various edge cases and shorthand forms that sing-box 1.13 accepts,
//! ensuring our deserialization handles them correctly.

use turntable::config::SingBoxConfig;
use turntable::config::dns::{DefaultDnsRule, Dns, DnsRuleAction, QueryType};
use turntable::config::inbound::Inbound;
use turntable::config::log::{Log, LogLevel};
use turntable::config::outbound::Outbound;
use turntable::config::route::{RouteRule, RuleAction, RuleSet, RuleSetFormat};

// ============================================================================
// Complete Config Parsing Tests
// ============================================================================

#[test]
fn test_parse_minimal_config() {
    let json = r#"{}"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert!(config.dns.is_none());
    assert!(config.inbounds.is_empty());
    assert!(config.outbounds.is_empty());
}

#[test]
fn test_parse_config_with_log() {
    let json = r#"{
        "log": {
            "level": "info",
            "timestamp": true
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.log.level, Some(LogLevel::Info));
    assert_eq!(config.log.timestamp, Some(true));
}

#[test]
fn test_parse_config_all_log_levels() {
    let levels = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];
    for level in levels {
        let json = format!(r#"{{"log": {{"level": "{}"}}}}"#, level);
        let config: SingBoxConfig = serde_json::from_str(&json).unwrap();
        assert!(config.log.level.is_some());
    }
}

// ============================================================================
// DNS Configuration Tests
// ============================================================================

#[test]
fn test_parse_dns_with_multiple_server_types() {
    let json = r#"{
        "dns": {
            "servers": [
                {"type": "udp", "tag": "udp-dns", "server": "8.8.8.8"},
                {"type": "tcp", "tag": "tcp-dns", "server": "8.8.4.4"},
                {"type": "https", "tag": "doh", "server": "1.1.1.1"},
                {"type": "tls", "tag": "dot", "server": "1.0.0.1"},
                {"type": "fakeip", "tag": "fakeip"},
                {"type": "local", "tag": "local"}
            ]
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let dns = config.dns.unwrap();
    assert_eq!(dns.servers.len(), 6);
}

#[test]
fn test_parse_dns_rule_with_single_string_rule_set() {
    let json = r#"{"rule_set": "my-rule", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.rule_set, vec!["my-rule"]);
}

#[test]
fn test_parse_dns_rule_with_array_rule_set() {
    let json = r#"{"rule_set": ["rule1", "rule2", "rule3"], "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.rule_set, vec!["rule1", "rule2", "rule3"]);
}

#[test]
fn test_parse_dns_rule_with_action_reject() {
    let json = r#"{"rule_set": "ads", "action": "reject"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, DnsRuleAction::Tagged(_)));
}

#[test]
fn test_parse_dns_rule_with_server_only_legacy() {
    let json = r#"{"clash_mode": "global", "server": "fakedns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, DnsRuleAction::Legacy(_)));
    if let DnsRuleAction::Legacy(legacy) = &rule.action {
        assert_eq!(legacy.server, "fakedns");
    }
}

#[test]
fn test_parse_dns_rule_with_query_type_strings() {
    let json = r#"{"query_type": ["A", "AAAA"], "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.query_type.len(), 2);
    assert!(matches!(&rule.query_type[0], QueryType::Name(s) if s == "A"));
    assert!(matches!(&rule.query_type[1], QueryType::Name(s) if s == "AAAA"));
}

#[test]
fn test_parse_dns_rule_with_query_type_numbers() {
    let json = r#"{"query_type": [1, 28], "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.query_type.len(), 2);
    assert!(matches!(&rule.query_type[0], QueryType::Number(1)));
    assert!(matches!(&rule.query_type[1], QueryType::Number(28)));
}

#[test]
fn test_parse_dns_rule_with_single_query_type() {
    let json = r#"{"query_type": "HTTPS", "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.query_type.len(), 1);
}

#[test]
fn test_parse_dns_rule_with_single_domain() {
    let json = r#"{"domain": "example.com", "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain, vec!["example.com"]);
}

#[test]
fn test_parse_dns_rule_with_multiple_domains() {
    let json = r#"{"domain": ["example.com", "test.com"], "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain.len(), 2);
}

#[test]
fn test_parse_dns_rule_with_domain_suffix() {
    let json = r#"{"domain_suffix": ".cn", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_suffix, vec![".cn"]);
}

#[test]
fn test_parse_dns_rule_with_domain_keyword() {
    let json = r#"{"domain_keyword": ["google", "facebook"], "server": "proxy"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_keyword, vec!["google", "facebook"]);
}

#[test]
fn test_parse_dns_rule_with_invert() {
    let json = r#"{"domain": "example.com", "invert": true, "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(rule.invert);
}

#[test]
fn test_parse_dns_with_fakeip_config() {
    let json = r#"{
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
            ],
            "fakeip": {
                "enabled": true,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let dns = config.dns.unwrap();
    assert!(dns.fakeip.is_some());
}

#[test]
fn test_parse_dns_strategy() {
    let strategies = ["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"];
    for strategy in strategies {
        let json = format!(r#"{{"dns": {{"strategy": "{}"}}}}"#, strategy);
        let config: SingBoxConfig = serde_json::from_str(&json).unwrap();
        assert!(config.dns.unwrap().strategy.is_some());
    }
}

// ============================================================================
// Route Configuration Tests
// ============================================================================

#[test]
fn test_parse_route_rule_with_single_inbound() {
    let json = r#"{"inbound": "tun-in", "action": "sniff"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.inbound, vec!["tun-in"]);
}

#[test]
fn test_parse_route_rule_with_multiple_inbounds() {
    let json = r#"{"inbound": ["tun-in", "mixed-in"], "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.inbound, vec!["tun-in", "mixed-in"]);
}

#[test]
fn test_parse_route_rule_with_single_port() {
    let json = r#"{"port": 53, "outbound": "dns-out"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.port, vec![53]);
}

#[test]
fn test_parse_route_rule_with_multiple_ports() {
    let json = r#"{"port": [80, 443, 8080], "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.port, vec![80, 443, 8080]);
}

#[test]
fn test_parse_route_rule_with_source_port_single() {
    let json = r#"{"source_port": 12345, "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.source_port, vec![12345]);
}

#[test]
fn test_parse_route_rule_with_action_sniff() {
    let json = r#"{"inbound": "tun-in", "action": "sniff"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::Sniff(_))));
}

#[test]
fn test_parse_route_rule_with_action_sniff_object() {
    let json = r#"{"inbound": "tun-in", "action": {"action": "sniff", "timeout": "300ms"}}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::Sniff(_))));
}

#[test]
fn test_parse_route_rule_with_action_reject() {
    let json = r#"{"rule_set": "ads", "action": "reject"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::Reject(_))));
}

#[test]
fn test_parse_route_rule_with_action_hijack_dns() {
    let json = r#"{"protocol": "dns", "action": "hijack-dns"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::HijackDns)));
}

#[test]
fn test_parse_route_rule_with_action_route() {
    let json = r#"{"domain": "example.com", "action": {"action": "route", "outbound": "proxy"}}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::Route(_))));
}

#[test]
fn test_parse_route_rule_with_legacy_outbound() {
    let json = r#"{"domain": "example.com", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.outbound, Some("direct".to_string()));
}

#[test]
fn test_parse_route_rule_with_single_rule_set() {
    let json = r#"{"rule_set": "geosite-cn", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.rule_set, vec!["geosite-cn"]);
}

#[test]
fn test_parse_route_rule_with_multiple_rule_sets() {
    let json = r#"{"rule_set": ["geosite-google", "geosite-youtube"], "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.rule_set, vec!["geosite-google", "geosite-youtube"]);
}

#[test]
fn test_parse_route_rule_with_single_domain_suffix() {
    let json = r#"{"domain_suffix": ".local", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_suffix, vec![".local"]);
}

#[test]
fn test_parse_route_rule_with_multiple_domain_suffix() {
    let json = r#"{"domain_suffix": [".cn", ".com.cn"], "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_suffix.len(), 2);
}

#[test]
fn test_parse_route_rule_with_ip_is_private() {
    let json = r#"{"ip_is_private": true, "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(rule.ip_is_private);
}

#[test]
fn test_parse_route_rule_with_source_ip_is_private() {
    let json = r#"{"source_ip_is_private": true, "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(rule.source_ip_is_private);
}

#[test]
fn test_parse_route_rule_with_single_protocol() {
    let json = r#"{"protocol": "bittorrent", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.protocol, vec!["bittorrent"]);
}

#[test]
fn test_parse_route_rule_with_multiple_protocols() {
    let json = r#"{"protocol": ["http", "tls"], "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.protocol, vec!["http", "tls"]);
}

#[test]
fn test_parse_route_rule_with_single_ip_cidr() {
    let json = r#"{"ip_cidr": "10.0.0.0/8", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.ip_cidr, vec!["10.0.0.0/8"]);
}

#[test]
fn test_parse_route_rule_with_multiple_ip_cidrs() {
    let json =
        r#"{"ip_cidr": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.ip_cidr.len(), 3);
}

#[test]
fn test_parse_route_rule_with_clash_mode() {
    let json = r#"{"clash_mode": "direct", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.clash_mode, Some("direct".to_string()));
}

#[test]
fn test_parse_logical_route_rule() {
    let json = r#"{
        "type": "logical",
        "mode": "or",
        "rules": [
            {"protocol": "dns"},
            {"port": 53}
        ],
        "action": "hijack-dns"
    }"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.rule_type, Some("logical".to_string()));
    assert_eq!(rule.rules.len(), 2);
}

#[test]
fn test_parse_logical_route_rule_and_mode() {
    let json = r#"{
        "type": "logical",
        "mode": "and",
        "rules": [
            {"domain_suffix": ".google.com"},
            {"network": "tcp"}
        ],
        "outbound": "proxy"
    }"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(rule.mode.is_some());
}

// ============================================================================
// Route Rule Set Tests
// ============================================================================

#[test]
fn test_parse_local_rule_set() {
    let json = r#"{"type": "local", "tag": "my-rules", "path": "/path/to/rules.srs"}"#;
    let rule_set: RuleSet = serde_json::from_str(json).unwrap();
    assert!(matches!(rule_set, RuleSet::Local(_)));
}

#[test]
fn test_parse_local_rule_set_with_format() {
    let json = r#"{"type": "local", "tag": "my-rules", "format": "source", "path": "/path/to/rules.json"}"#;
    let rule_set: RuleSet = serde_json::from_str(json).unwrap();
    if let RuleSet::Local(local) = rule_set {
        assert!(matches!(local.format, Some(RuleSetFormat::Source)));
    }
}

#[test]
fn test_parse_remote_rule_set() {
    let json = r#"{"type": "remote", "tag": "geosite-cn", "url": "https://example.com/rules.srs"}"#;
    let rule_set: RuleSet = serde_json::from_str(json).unwrap();
    assert!(matches!(rule_set, RuleSet::Remote(_)));
}

#[test]
fn test_parse_remote_rule_set_with_options() {
    let json = r#"{
        "type": "remote",
        "tag": "geosite-cn",
        "url": "https://example.com/rules.srs",
        "download_detour": "proxy",
        "update_interval": "24h"
    }"#;
    let rule_set: RuleSet = serde_json::from_str(json).unwrap();
    if let RuleSet::Remote(remote) = rule_set {
        assert_eq!(remote.download_detour, Some("proxy".to_string()));
        assert_eq!(remote.update_interval, Some("24h".to_string()));
    }
}

// ============================================================================
// Inbound Configuration Tests
// ============================================================================

#[test]
fn test_parse_tun_inbound() {
    let json = r#"{
        "type": "tun",
        "tag": "tun-in",
        "mtu": 9000,
        "address": ["172.16.0.1/30", "fd00::1/126"],
        "auto_route": true,
        "strict_route": true,
        "stack": "mixed"
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    assert!(matches!(inbound, Inbound::Tun(_)));
}

#[test]
fn test_parse_tun_inbound_with_single_address() {
    let json = r#"{
        "type": "tun",
        "tag": "tun-in",
        "address": "172.16.0.1/30"
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    if let Inbound::Tun(tun) = inbound {
        assert_eq!(tun.address.len(), 1);
    }
}

#[test]
fn test_parse_mixed_inbound() {
    let json = r#"{
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": 7890
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    assert!(matches!(inbound, Inbound::Mixed(_)));
}

#[test]
fn test_parse_socks_inbound() {
    let json = r#"{
        "type": "socks",
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "listen_port": 1080
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    assert!(matches!(inbound, Inbound::Socks(_)));
}

#[test]
fn test_parse_http_inbound() {
    let json = r#"{
        "type": "http",
        "tag": "http-in",
        "listen": "127.0.0.1",
        "listen_port": 8080
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    assert!(matches!(inbound, Inbound::Http(_)));
}

// ============================================================================
// Outbound Configuration Tests
// ============================================================================

#[test]
fn test_parse_direct_outbound() {
    let json = r#"{"type": "direct", "tag": "direct"}"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Direct(_)));
}

#[test]
fn test_parse_block_outbound() {
    let json = r#"{"type": "block", "tag": "block"}"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Block(_)));
}

#[test]
fn test_parse_dns_outbound() {
    let json = r#"{"type": "dns", "tag": "dns-out"}"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Dns(_)));
}

#[test]
fn test_parse_selector_outbound() {
    let json = r#"{
        "type": "selector",
        "tag": "select",
        "outbounds": ["direct", "proxy"],
        "default": "proxy"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::Selector(selector) = outbound {
        assert_eq!(selector.outbounds.len(), 2);
        assert_eq!(selector.default, Some("proxy".to_string()));
    }
}

#[test]
fn test_parse_urltest_outbound() {
    let json = r#"{
        "type": "urltest",
        "tag": "auto",
        "outbounds": ["proxy1", "proxy2"],
        "url": "https://www.gstatic.com/generate_204",
        "interval": "5m"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::UrlTest(_)));
}

#[test]
fn test_parse_shadowsocks_outbound() {
    let json = r#"{
        "type": "shadowsocks",
        "tag": "ss",
        "server": "example.com",
        "server_port": 8388,
        "method": "2022-blake3-aes-128-gcm",
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Shadowsocks(_)));
}

#[test]
fn test_parse_vmess_outbound() {
    let json = r#"{
        "type": "vmess",
        "tag": "vmess",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "security": "auto"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VMess(_)));
}

#[test]
fn test_parse_vmess_outbound_with_transport() {
    let json = r#"{
        "type": "vmess",
        "tag": "vmess-ws",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "transport": {
            "type": "ws",
            "path": "/ws"
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VMess(_)));
}

#[test]
fn test_parse_trojan_outbound() {
    let json = r#"{
        "type": "trojan",
        "tag": "trojan",
        "server": "example.com",
        "server_port": 443,
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Trojan(_)));
}

#[test]
fn test_parse_vless_outbound() {
    let json = r#"{
        "type": "vless",
        "tag": "vless",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VLess(_)));
}

#[test]
fn test_parse_vless_with_reality() {
    let json = r#"{
        "type": "vless",
        "tag": "vless-reality",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": true,
            "server_name": "www.microsoft.com",
            "reality": {
                "enabled": true,
                "public_key": "key",
                "short_id": "id"
            }
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VLess(_)));
}

#[test]
fn test_parse_hysteria_outbound() {
    let json = r#"{
        "type": "hysteria",
        "tag": "hy",
        "server": "example.com",
        "server_port": 443,
        "up_mbps": 100,
        "down_mbps": 100,
        "auth_str": "password"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Hysteria(_)));
}

#[test]
fn test_parse_hysteria_with_port_hopping() {
    // server_ports as array format (since sing-box 1.12.0)
    let json = r#"{
        "type": "hysteria",
        "tag": "hy",
        "server": "example.com",
        "server_ports": ["20000:30000"],
        "hop_interval": "30s",
        "up_mbps": 100,
        "down_mbps": 100,
        "auth_str": "password"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::Hysteria(hy) = outbound {
        assert_eq!(hy.server_ports, vec!["20000:30000".to_string()]);
        assert_eq!(hy.hop_interval, Some("30s".to_string()));
    } else {
        panic!("Expected Hysteria outbound");
    }
}

#[test]
fn test_parse_hysteria2_outbound() {
    let json = r#"{
        "type": "hysteria2",
        "tag": "hy2",
        "server": "example.com",
        "server_port": 443,
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Hysteria2(_)));
}

#[test]
fn test_parse_tuic_outbound() {
    let json = r#"{
        "type": "tuic",
        "tag": "tuic",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Tuic(_)));
}

#[test]
fn test_parse_wireguard_outbound() {
    let json = r#"{
        "type": "wireguard",
        "tag": "wg",
        "server": "example.com",
        "server_port": 51820,
        "local_address": ["10.0.0.2/32"],
        "private_key": "key",
        "peer_public_key": "peer_key"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::WireGuard(_)));
}

#[test]
fn test_parse_ssh_outbound() {
    let json = r#"{
        "type": "ssh",
        "tag": "ssh",
        "server": "example.com",
        "server_port": 22,
        "user": "root",
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Ssh(_)));
}

// ============================================================================
// NTP Configuration Tests
// ============================================================================

#[test]
fn test_parse_ntp_config() {
    let json = r#"{
        "ntp": {
            "enabled": true,
            "server": "time.apple.com",
            "server_port": 123
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let ntp = config.ntp.unwrap();
    assert!(ntp.enabled);
    assert_eq!(ntp.server, Some("time.apple.com".to_string()));
}

// ============================================================================
// Experimental Configuration Tests
// ============================================================================

#[test]
fn test_parse_experimental_cache_file() {
    let json = r#"{
        "experimental": {
            "cache_file": {
                "enabled": true,
                "store_fakeip": true
            }
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let exp = config.experimental.unwrap();
    let cache = exp.cache_file.unwrap();
    assert!(cache.enabled);
    assert!(cache.store_fakeip);
}

#[test]
fn test_parse_experimental_clash_api() {
    let json = r#"{
        "experimental": {
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "secret": "test",
                "default_mode": "rule"
            }
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let exp = config.experimental.unwrap();
    let clash = exp.clash_api.unwrap();
    assert_eq!(clash.external_controller, Some("0.0.0.0:9090".to_string()));
}

#[test]
fn test_parse_experimental_clash_api_cors() {
    let json = r#"{
        "experimental": {
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "access_control_allow_origin": ["http://localhost", "https://yacd.haishan.me"],
                "access_control_allow_private_network": true
            }
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let exp = config.experimental.unwrap();
    let clash = exp.clash_api.unwrap();
    assert_eq!(clash.access_control_allow_origin.len(), 2);
    assert!(clash.access_control_allow_private_network);
}

// ============================================================================
// Full Config Integration Tests
// ============================================================================

#[test]
fn test_parse_full_realistic_config() {
    let json = r#"{
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": [
                {"type": "https", "tag": "secure", "server": "1.1.1.1"},
                {"type": "https", "tag": "local", "server": "dns.alidns.com"},
                {"type": "fakeip", "tag": "fakedns"}
            ],
            "rules": [
                {"clash_mode": "global", "server": "fakedns"},
                {"clash_mode": "direct", "server": "local"},
                {"rule_set": "ads", "action": "reject"},
                {"query_type": ["A", "AAAA"], "server": "fakedns"}
            ],
            "final": "secure",
            "strategy": "prefer_ipv6"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.16.0.1/30", "fd00::1/126"],
                "auto_route": true,
                "stack": "mixed"
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "select", "outbounds": ["direct", "proxy"]},
            {"type": "direct", "tag": "direct"},
            {"type": "shadowsocks", "tag": "proxy", "server": "example.com", "server_port": 8388, "method": "aes-256-gcm", "password": "secret"}
        ],
        "route": {
            "rules": [
                {"inbound": "tun-in", "action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": true, "outbound": "direct"},
                {"rule_set": "geosite-cn", "outbound": "direct"}
            ],
            "rule_set": [
                {"type": "remote", "tag": "ads", "url": "https://example.com/ads.srs"},
                {"type": "remote", "tag": "geosite-cn", "url": "https://example.com/cn.srs"}
            ],
            "final": "select",
            "auto_detect_interface": true
        },
        "experimental": {
            "cache_file": {"enabled": true, "store_fakeip": true},
            "clash_api": {"external_controller": "0.0.0.0:9090"}
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();

    // Verify all sections parsed
    assert!(config.dns.is_some());
    assert_eq!(config.inbounds.len(), 1);
    assert_eq!(config.outbounds.len(), 3);
    assert!(config.route.is_some());
    assert!(config.experimental.is_some());

    // Verify DNS
    let dns = config.dns.unwrap();
    assert_eq!(dns.servers.len(), 3);
    assert_eq!(dns.rules.len(), 4);

    // Verify route
    let route = config.route.unwrap();
    assert_eq!(route.rules.len(), 4);
    assert_eq!(route.rule_set.len(), 2);
}

#[test]
fn test_roundtrip_serialization() {
    let original = SingBoxConfig {
        log: Log {
            level: Some(LogLevel::Info),
            timestamp: Some(true),
            ..Default::default()
        },
        dns: Some(Dns {
            r#final: Some("local".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let json = serde_json::to_string_pretty(&original).unwrap();
    let parsed: SingBoxConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.log.level, Some(LogLevel::Info));
    assert_eq!(parsed.log.timestamp, Some(true));
    assert!(parsed.dns.is_some());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_parse_empty_arrays() {
    let json = r#"{
        "inbounds": [],
        "outbounds": [],
        "route": {
            "rules": [],
            "rule_set": []
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert!(config.inbounds.is_empty());
    assert!(config.outbounds.is_empty());
}

#[test]
fn test_parse_unknown_fields_are_ignored() {
    let json = r#"{
        "log": {"level": "info"},
        "unknown_field": "should be ignored",
        "another_unknown": {"nested": "value"}
    }"#;
    // This should not fail - unknown fields should be ignored
    let result: Result<SingBoxConfig, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_parse_route_rule_all_match_conditions() {
    let json = r#"{
        "inbound": ["tun-in"],
        "ip_version": 4,
        "network": ["tcp", "udp"],
        "auth_user": ["user1"],
        "protocol": ["http"],
        "domain": ["example.com"],
        "domain_suffix": [".com"],
        "domain_keyword": ["test"],
        "domain_regex": [".*\\.example\\.com"],
        "source_ip_cidr": ["10.0.0.0/8"],
        "source_ip_is_private": false,
        "ip_cidr": ["8.8.8.0/24"],
        "ip_is_private": false,
        "source_port": [12345],
        "source_port_range": ["1000:2000"],
        "port": [80, 443],
        "port_range": ["8000:9000"],
        "process_name": ["chrome"],
        "process_path": ["/usr/bin/chrome"],
        "clash_mode": "rule",
        "rule_set": ["my-rules"],
        "invert": false,
        "outbound": "proxy"
    }"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(!rule.inbound.is_empty());
    assert!(!rule.network.is_empty());
    assert!(!rule.domain.is_empty());
}

#[test]
fn test_parse_dns_rule_all_match_conditions() {
    let json = r#"{
        "inbound": ["tun-in"],
        "ip_version": 4,
        "query_type": ["A"],
        "network": "tcp",
        "protocol": ["dns"],
        "domain": ["example.com"],
        "domain_suffix": [".com"],
        "domain_keyword": ["test"],
        "source_ip_cidr": ["10.0.0.0/8"],
        "ip_cidr": ["8.8.8.0/24"],
        "port": [53],
        "clash_mode": "rule",
        "rule_set": ["my-rules"],
        "invert": false,
        "server": "local"
    }"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(!rule.inbound.is_empty());
    assert!(!rule.domain.is_empty());
}

// ============================================================================
// Sing-box 1.13 Specific Features Tests
// ============================================================================

#[test]
fn test_parse_route_rule_with_network_icmp() {
    // ICMP support added in 1.13.0
    let json = r#"{"network": "icmp", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.network, vec!["icmp"]);
}

#[test]
fn test_parse_route_rule_with_preferred_by() {
    // preferred_by added in 1.13.0
    let json = r#"{"preferred_by": ["proxy1", "proxy2"], "outbound": "select"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.preferred_by, vec!["proxy1", "proxy2"]);
}

#[test]
fn test_parse_route_with_default_domain_resolver_string() {
    let json = r#"{
        "route": {
            "default_domain_resolver": "local"
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert!(config.route.is_some());
}

#[test]
fn test_parse_selector_with_interrupt_exist_connections() {
    let json = r#"{
        "type": "selector",
        "tag": "select",
        "outbounds": ["a", "b"],
        "interrupt_exist_connections": true
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::Selector(selector) = outbound {
        assert!(selector.interrupt_exist_connections);
    }
}

#[test]
fn test_parse_urltest_with_idle_timeout() {
    let json = r#"{
        "type": "urltest",
        "tag": "auto",
        "outbounds": ["a", "b"],
        "idle_timeout": "30m"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::UrlTest(urltest) = outbound {
        assert_eq!(urltest.idle_timeout, Some("30m".to_string()));
    }
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_parse_dns_server_with_domain_resolver_string() {
    let json = r#"{
        "dns": {
            "servers": [
                {"type": "https", "tag": "doh", "server": "1.1.1.1", "domain_resolver": "local"},
                {"type": "udp", "tag": "local", "server": "223.5.5.5"}
            ]
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert!(config.dns.is_some());
}

#[test]
fn test_parse_route_rule_with_single_domain() {
    let json = r#"{"domain": "example.com", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain, vec!["example.com"]);
}

#[test]
fn test_parse_route_rule_with_single_network() {
    let json = r#"{"network": "tcp", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.network, vec!["tcp"]);
}

#[test]
fn test_parse_route_rule_with_single_source_ip_cidr() {
    let json = r#"{"source_ip_cidr": "192.168.1.0/24", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.source_ip_cidr, vec!["192.168.1.0/24"]);
}

#[test]
fn test_parse_route_rule_with_single_process_name() {
    let json = r#"{"process_name": "chrome.exe", "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.process_name, vec!["chrome.exe"]);
}

#[test]
fn test_parse_route_rule_with_single_domain_keyword() {
    let json = r#"{"domain_keyword": "google", "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_keyword, vec!["google"]);
}

#[test]
fn test_parse_route_rule_with_single_domain_regex() {
    let json = r#"{"domain_regex": ".*\\.example\\.com$", "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.domain_regex.len(), 1);
}

#[test]
fn test_parse_route_rule_with_single_auth_user() {
    let json = r#"{"auth_user": "admin", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.auth_user, vec!["admin"]);
}

#[test]
fn test_parse_route_rule_with_single_client() {
    let json = r#"{"client": "chrome", "outbound": "proxy"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.client, vec!["chrome"]);
}

#[test]
fn test_parse_route_rule_with_single_wifi_ssid() {
    let json = r#"{"wifi_ssid": "MyWiFi", "outbound": "direct"}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.wifi_ssid, vec!["MyWiFi"]);
}

#[test]
fn test_parse_dns_rule_with_single_inbound() {
    let json = r#"{"inbound": "tun-in", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.inbound, vec!["tun-in"]);
}

#[test]
fn test_parse_dns_rule_with_single_protocol() {
    let json = r#"{"protocol": "quic", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.protocol, vec!["quic"]);
}

#[test]
fn test_parse_dns_rule_with_single_source_ip_cidr() {
    let json = r#"{"source_ip_cidr": "10.0.0.0/8", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.source_ip_cidr, vec!["10.0.0.0/8"]);
}

#[test]
fn test_parse_dns_rule_with_single_ip_cidr() {
    let json = r#"{"ip_cidr": "8.8.8.0/24", "server": "local"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.ip_cidr, vec!["8.8.8.0/24"]);
}

#[test]
fn test_parse_outbound_with_domain_resolver_string() {
    let json = r#"{
        "type": "direct",
        "tag": "direct",
        "domain_resolver": "local"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Direct(_)));
}

#[test]
fn test_parse_tls_config_with_utls() {
    let json = r#"{
        "type": "trojan",
        "tag": "trojan",
        "server": "example.com",
        "server_port": 443,
        "password": "secret",
        "tls": {
            "enabled": true,
            "server_name": "example.com",
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Trojan(_)));
}

#[test]
fn test_parse_tls_config_with_ech() {
    let json = r#"{
        "type": "trojan",
        "tag": "trojan",
        "server": "example.com",
        "server_port": 443,
        "password": "secret",
        "tls": {
            "enabled": true,
            "ech": {
                "enabled": true,
                "config": ["base64config"]
            }
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Trojan(_)));
}

#[test]
fn test_parse_multiplex_config() {
    let json = r#"{
        "type": "shadowsocks",
        "tag": "ss",
        "server": "example.com",
        "server_port": 8388,
        "method": "aes-256-gcm",
        "password": "secret",
        "multiplex": {
            "enabled": true,
            "protocol": "h2mux",
            "max_connections": 4,
            "padding": true
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::Shadowsocks(_)));
}

#[test]
fn test_parse_v2ray_transport_http() {
    let json = r#"{
        "type": "vmess",
        "tag": "vmess-http",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "transport": {
            "type": "http",
            "host": ["example.com"],
            "path": "/path"
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VMess(_)));
}

#[test]
fn test_parse_v2ray_transport_grpc() {
    let json = r#"{
        "type": "vmess",
        "tag": "vmess-grpc",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "transport": {
            "type": "grpc",
            "service_name": "GunService"
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VMess(_)));
}

#[test]
fn test_parse_v2ray_transport_httpupgrade() {
    let json = r#"{
        "type": "vless",
        "tag": "vless-httpupgrade",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "transport": {
            "type": "httpupgrade",
            "host": "example.com",
            "path": "/ws"
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    assert!(matches!(outbound, Outbound::VLess(_)));
}

#[test]
fn test_parse_inline_rule_set() {
    let json = r#"{
        "type": "inline",
        "tag": "my-inline-rules",
        "rules": [
            {"domain": "example.com"},
            {"domain_suffix": ".test.com"}
        ]
    }"#;
    let rule_set: RuleSet = serde_json::from_str(json).unwrap();
    assert!(matches!(rule_set, RuleSet::Inline(_)));
}

#[test]
fn test_parse_route_action_resolve() {
    let json = r#"{"domain": "example.com", "action": {"action": "resolve", "server": "local"}}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::Resolve(_))));
}

#[test]
fn test_parse_route_action_route_options() {
    let json = r#"{"domain": "example.com", "action": {"action": "route-options", "override_address": "1.2.3.4"}}"#;
    let rule: RouteRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, Some(RuleAction::RouteOptions(_))));
}

#[test]
fn test_parse_hysteria2_with_port_hopping() {
    // server_ports as array format (correct sing-box format)
    let json = r#"{
        "type": "hysteria2",
        "tag": "hy2",
        "server": "example.com",
        "server_port": 443,
        "server_ports": ["20000:40000"],
        "hop_interval": "30s",
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::Hysteria2(hy2) = outbound {
        assert_eq!(hy2.server_ports, vec!["20000:40000".to_string()]);
        assert_eq!(hy2.hop_interval, Some("30s".to_string()));
    }
}

#[test]
fn test_parse_wireguard_with_multiple_peers() {
    let json = r#"{
        "type": "wireguard",
        "tag": "wg",
        "local_address": ["10.0.0.2/32"],
        "private_key": "key",
        "peers": [
            {"server": "peer1.example.com", "server_port": 51820, "public_key": "key1", "allowed_ips": ["0.0.0.0/0"]},
            {"server": "peer2.example.com", "server_port": 51820, "public_key": "key2", "allowed_ips": ["0.0.0.0/0"]}
        ]
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    if let Outbound::WireGuard(wg) = outbound {
        assert_eq!(wg.peers.len(), 2);
    }
}

#[test]
fn test_parse_config_with_endpoints() {
    let json = r#"{
        "endpoints": [
            {
                "type": "wireguard",
                "tag": "wg-ep",
                "local_address": ["10.0.0.1/24"],
                "private_key": "key",
                "peers": [{"public_key": "peer_key", "allowed_ips": ["0.0.0.0/0"]}]
            }
        ]
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.endpoints.len(), 1);
}

#[test]
fn test_parse_dns_predefined_action() {
    // DNS rule actions are flattened, so action tag is at the same level as other fields
    let json = r#"{"domain": "blocked.com", "action": "predefined", "rcode": "NXDOMAIN"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, DnsRuleAction::Tagged(_)));
}

#[test]
fn test_parse_dns_route_options_action() {
    // DNS rule actions are flattened, so action tag is at the same level as other fields
    let json = r#"{"domain": "example.com", "action": "route-options", "disable_cache": true}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert!(matches!(rule.action, DnsRuleAction::Tagged(_)));
}

#[test]
fn test_parse_mixed_query_types() {
    // Mix of string and number query types
    let json = r#"{"query_type": ["A", 28, "HTTPS"], "server": "dns"}"#;
    let rule: DefaultDnsRule = serde_json::from_str(json).unwrap();
    assert_eq!(rule.query_type.len(), 3);
    assert!(matches!(&rule.query_type[0], QueryType::Name(s) if s == "A"));
    assert!(matches!(&rule.query_type[1], QueryType::Number(28)));
    assert!(matches!(&rule.query_type[2], QueryType::Name(s) if s == "HTTPS"));
}

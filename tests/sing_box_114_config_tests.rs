//! Comprehensive tests for sing-box 1.14 configuration parsing.
//!
//! These tests focus on the schema additions and behavioral surface introduced
//! in sing-box 1.14.

use turntable::config::dns::{DnsRule, DnsRuleAction, QueryType, RCode, TaggedDnsRuleAction};
use turntable::config::inbound::Inbound;
use turntable::config::outbound::Outbound;
use turntable::config::route::{RuleAction, RuleSet};
use turntable::config::shared::{
    CertificateProvider, CertificateProviderRef, HttpClient, HttpClientRef,
};
use turntable::config::version::SingBoxVersion;
use turntable::config::SingBoxConfig;

#[test]
fn test_parse_dns_optimistic_true_shorthand() {
    let json = r#"{
        "dns": {
            "optimistic": true
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let dns = config.dns.unwrap();
    let optimistic = dns.optimistic.unwrap();
    assert!(optimistic.enabled);
    assert_eq!(optimistic.timeout, None);
}

#[test]
fn test_parse_dns_optimistic_and_response_matching_fields() {
    let json = r#"{
        "dns": {
            "servers": [
                {"type": "local", "tag": "local"},
                {"type": "https", "tag": "remote", "server": "1.1.1.1"}
            ],
            "optimistic": {
                "enabled": true,
                "timeout": "12h"
            },
            "rules": [
                {
                    "action": "evaluate",
                    "server": "remote",
                    "disable_optimistic_cache": true
                },
                {
                    "match_response": true,
                    "response_rcode": "NOERROR",
                    "response_answer": ["example.com. 60 IN A 1.1.1.1"],
                    "response_ns": ["example.com. 60 IN NS ns1.example.com."],
                    "response_extra": ["ns1.example.com. 60 IN A 1.1.1.2"],
                    "ip_cidr": ["1.1.1.0/24"],
                    "ip_is_private": false,
                    "ip_accept_any": true,
                    "source_mac_address": ["00:11:22:33:44:55"],
                    "source_hostname": ["laptop"],
                    "package_name_regex": ["^com\\.example\\..+$"],
                    "query_type": ["A", 28],
                    "action": "route",
                    "server": "local",
                    "disable_optimistic_cache": true
                },
                {
                    "action": "respond"
                }
            ]
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let dns = config.dns.unwrap();

    let optimistic = dns.optimistic.unwrap();
    assert!(optimistic.enabled);
    assert_eq!(optimistic.timeout.as_deref(), Some("12h"));

    let evaluate_rule = match &dns.rules[0] {
        DnsRule::Default(rule) => rule,
        other => panic!("expected default dns rule, got {other:?}"),
    };
    assert!(matches!(
        &evaluate_rule.action,
        DnsRuleAction::Tagged(TaggedDnsRuleAction::Evaluate(action))
        if action.server == "remote" && action.disable_optimistic_cache
    ));

    let response_rule = match &dns.rules[1] {
        DnsRule::Default(rule) => rule,
        other => panic!("expected default dns rule, got {other:?}"),
    };
    assert!(response_rule.match_response);
    assert_eq!(response_rule.response_rcode, Some(RCode::NoError));
    assert_eq!(response_rule.response_answer.len(), 1);
    assert_eq!(response_rule.response_ns.len(), 1);
    assert_eq!(response_rule.response_extra.len(), 1);
    assert_eq!(response_rule.source_mac_address, vec!["00:11:22:33:44:55"]);
    assert_eq!(response_rule.source_hostname, vec!["laptop"]);
    assert_eq!(
        response_rule.package_name_regex,
        vec!["^com\\.example\\..+$"]
    );
    assert!(matches!(&response_rule.query_type[0], QueryType::Name(name) if name == "A"));
    assert!(matches!(
        &response_rule.query_type[1],
        QueryType::Number(28)
    ));
    assert!(matches!(
        &response_rule.action,
        DnsRuleAction::Tagged(TaggedDnsRuleAction::Route(action))
        if action.server == "local" && action.disable_optimistic_cache
    ));

    let respond_rule = match &dns.rules[2] {
        DnsRule::Default(rule) => rule,
        other => panic!("expected default dns rule, got {other:?}"),
    };
    assert!(matches!(
        &respond_rule.action,
        DnsRuleAction::Tagged(TaggedDnsRuleAction::Respond)
    ));
}

#[test]
fn test_parse_certificate_providers_and_tls_reference() {
    let json = r#"{
        "certificate_providers": [
            {
                "type": "acme",
                "tag": "acme-cert",
                "domain": ["example.com"],
                "email": "admin@example.com",
                "account_key": "pem-account-key",
                "key_type": "rsa4096",
                "detour": "proxy"
            },
            {
                "type": "tailscale",
                "tag": "tailscale-cert",
                "endpoint": "ts-ep"
            },
            {
                "type": "cloudflare-origin-ca",
                "tag": "cf-cert",
                "domain": ["*.example.com"],
                "api_token": "token",
                "request_type": "origin-ecc",
                "requested_validity": 365,
                "detour": "proxy"
            }
        ],
        "inbounds": [
            {
                "type": "trojan",
                "tag": "trojan-in",
                "listen": "0.0.0.0",
                "listen_port": 443,
                "users": [{"password": "secret"}],
                "tls": {
                    "enabled": true,
                    "certificate_provider": "acme-cert"
                }
            }
        ]
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.certificate_providers.len(), 3);
    assert!(matches!(
        &config.certificate_providers[0],
        CertificateProvider::Acme(provider)
        if provider.tag == "acme-cert"
            && provider.account_key.as_deref() == Some("pem-account-key")
            && provider.key_type.as_deref() == Some("rsa4096")
            && provider.detour.as_deref() == Some("proxy")
    ));
    assert!(matches!(
        &config.certificate_providers[1],
        CertificateProvider::Tailscale(provider)
        if provider.tag == "tailscale-cert" && provider.endpoint == "ts-ep"
    ));
    assert!(matches!(
        &config.certificate_providers[2],
        CertificateProvider::CloudflareOriginCa(provider)
        if provider.tag == "cf-cert"
            && provider.api_token.as_deref() == Some("token")
            && provider.request_type.as_deref() == Some("origin-ecc")
            && provider.requested_validity == Some(365)
    ));

    let inbound = match &config.inbounds[0] {
        Inbound::Trojan(inbound) => inbound,
        other => panic!("expected trojan inbound, got {other:?}"),
    };
    let tls = inbound.tls.as_ref().unwrap();
    assert!(matches!(
        tls.certificate_provider.as_ref().unwrap(),
        CertificateProviderRef::Tag(tag) if tag == "acme-cert"
    ));
}

#[test]
fn test_parse_inline_certificate_provider_with_dns01_fields() {
    let json = r#"{
        "inbounds": [
            {
                "type": "trojan",
                "tag": "trojan-in",
                "listen": "0.0.0.0",
                "listen_port": 443,
                "users": [{"password": "secret"}],
                "tls": {
                    "enabled": true,
                    "certificate_provider": {
                        "type": "acme",
                        "tag": "inline-acme",
                        "domain": ["example.com"],
                        "email": "admin@example.com",
                        "account_key": "pem-account-key",
                        "key_type": "ed25519",
                        "detour": "proxy",
                        "dns01_challenge": {
                            "ttl": "5m",
                            "propagation_delay": "10s",
                            "propagation_timeout": "30m",
                            "resolvers": ["1.1.1.1", "8.8.8.8"],
                            "override_domain": "_acme-challenge.delegate.example.com",
                            "provider": "cloudflare",
                            "api_token": "token",
                            "zone_token": "zone-token"
                        }
                    }
                }
            }
        ]
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let inbound = match &config.inbounds[0] {
        Inbound::Trojan(inbound) => inbound,
        other => panic!("expected trojan inbound, got {other:?}"),
    };
    let tls = inbound.tls.as_ref().unwrap();

    let provider = match tls.certificate_provider.as_ref().unwrap() {
        CertificateProviderRef::Inline(provider) => provider,
        other => panic!("expected inline certificate provider, got {other:?}"),
    };

    assert!(matches!(
        provider.as_ref(),
        CertificateProvider::Acme(acme)
        if acme.tag == "inline-acme"
            && acme.account_key.as_deref() == Some("pem-account-key")
            && acme.key_type.as_deref() == Some("ed25519")
            && acme.detour.as_deref() == Some("proxy")
            && acme.dns01_challenge.as_ref().is_some_and(|challenge| {
                challenge.ttl.as_deref() == Some("5m")
                    && challenge.propagation_delay.as_deref() == Some("10s")
                    && challenge.propagation_timeout.as_deref() == Some("30m")
                    && challenge.resolvers == vec!["1.1.1.1", "8.8.8.8"]
                    && challenge.override_domain.as_deref()
                        == Some("_acme-challenge.delegate.example.com")
            })
    ));
}

#[test]
fn test_parse_route_neighbor_and_rule_fields() {
    let json = r#"{
        "route": {
            "find_neighbor": true,
            "dhcp_lease_files": ["/var/lib/misc/dnsmasq.leases"],
            "rules": [
                {
                    "source_mac_address": ["00:11:22:33:44:55"],
                    "source_hostname": ["desktop"],
                    "package_name_regex": ["^com\\.example\\..+$"],
                    "action": {
                        "action": "resolve",
                        "disable_optimistic_cache": true,
                        "server": "dns"
                    }
                }
            ],
            "rule_set": [
                {
                    "type": "inline",
                    "tag": "apps",
                    "rules": [
                        {
                            "package_name_regex": ["^com\\.example\\..+$"]
                        }
                    ]
                }
            ]
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let route = config.route.unwrap();
    assert!(route.find_neighbor);
    assert_eq!(route.dhcp_lease_files, vec!["/var/lib/misc/dnsmasq.leases"]);

    let rule = &route.rules[0];
    assert_eq!(rule.source_mac_address, vec!["00:11:22:33:44:55"]);
    assert_eq!(rule.source_hostname, vec!["desktop"]);
    assert_eq!(rule.package_name_regex, vec!["^com\\.example\\..+$"]);
    assert!(matches!(
        rule.action.as_ref().unwrap(),
        RuleAction::Resolve(action)
        if action.server.as_deref() == Some("dns") && action.disable_optimistic_cache
    ));

    let rule_set = match &route.rule_set[0] {
        RuleSet::Inline(rule_set) => rule_set,
        other => panic!("expected inline rule set, got {other:?}"),
    };
    assert_eq!(
        rule_set.rules[0].package_name_regex,
        vec!["^com\\.example\\..+$"]
    );
}

#[test]
fn test_parse_tun_and_hysteria2_114_fields() {
    let json = r#"{
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.16.0.1/30"],
                "auto_route": true,
                "auto_redirect": true,
                "include_mac_address": ["00:11:22:33:44:55"]
            },
            {
                "type": "hysteria2",
                "tag": "hy2-in",
                "listen": "0.0.0.0",
                "listen_port": 443,
                "users": [{"name": "user", "password": "secret"}],
                "tls": {"enabled": true},
                "bbr_profile": "aggressive"
            }
        ],
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "hy2-out",
                "server": "example.com",
                "server_ports": ["20000:30000"],
                "hop_interval": "30s",
                "hop_interval_max": "45s",
                "password": "secret",
                "tls": {"enabled": true},
                "bbr_profile": "conservative"
            }
        ],
        "experimental": {
            "cache_file": {
                "enabled": true,
                "store_dns": true
            }
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();

    let tun = match &config.inbounds[0] {
        Inbound::Tun(inbound) => inbound,
        other => panic!("expected tun inbound, got {other:?}"),
    };
    assert_eq!(tun.include_mac_address, vec!["00:11:22:33:44:55"]);

    let hy2_in = match &config.inbounds[1] {
        Inbound::Hysteria2(inbound) => inbound,
        other => panic!("expected hysteria2 inbound, got {other:?}"),
    };
    assert_eq!(hy2_in.bbr_profile.as_deref(), Some("aggressive"));

    let hy2_out = match &config.outbounds[0] {
        Outbound::Hysteria2(outbound) => outbound,
        other => panic!("expected hysteria2 outbound, got {other:?}"),
    };
    assert_eq!(hy2_out.hop_interval_max.as_deref(), Some("45s"));
    assert_eq!(hy2_out.bbr_profile.as_deref(), Some("conservative"));

    let cache_file = config.experimental.unwrap().cache_file.unwrap();
    assert!(cache_file.store_dns);
}

#[test]
fn test_parse_cloudflared_inbound() {
    let json = r#"{
        "type": "cloudflared",
        "tag": "cf-tunnel",
        "token": "base64-token",
        "ha_connections": 4,
        "protocol": "quic",
        "post_quantum": true,
        "edge_ip_version": 6,
        "datagram_version": "v3",
        "grace_period": "30s",
        "region": "us",
        "control_dialer": {
            "detour": "proxy"
        },
        "tunnel_dialer": {
            "bind_interface": "eth0"
        }
    }"#;

    let inbound: Inbound = serde_json::from_str(json).unwrap();
    assert!(matches!(
        inbound,
        Inbound::Cloudflared(cloudflared)
        if cloudflared.tag.as_deref() == Some("cf-tunnel")
            && cloudflared.token == "base64-token"
            && cloudflared.ha_connections == Some(4)
            && cloudflared.protocol.as_deref() == Some("quic")
            && cloudflared.post_quantum
            && cloudflared.edge_ip_version == Some(6)
            && cloudflared.datagram_version.as_deref() == Some("v3")
            && cloudflared.region.as_deref() == Some("us")
            && cloudflared.control_dialer.detour.as_deref() == Some("proxy")
            && cloudflared.tunnel_dialer.bind_interface.as_deref() == Some("eth0")
    ));
}

#[test]
fn test_parse_top_level_http_clients() {
    let json = r#"{
        "http_clients": [
            {
                "tag": "shared-client",
                "engine": "apple",
                "version": 2,
                "disable_version_fallback": true,
                "headers": {"X-Test": "1"},
                "idle_timeout": "30s",
                "keep_alive_period": "10s",
                "max_concurrent_streams": 128,
                "initial_packet_size": 1200,
                "disable_path_mtu_discovery": true,
                "tls": {"enabled": true, "server_name": "example.com"}
            }
        ]
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.http_clients.len(), 1);
    let client = &config.http_clients[0];
    assert_eq!(client.tag, "shared-client");
    assert_eq!(client.engine.as_deref(), Some("apple"));
    assert_eq!(client.version, Some(2));
    assert!(client.disable_version_fallback);
    assert_eq!(client.headers.get("X-Test").map(String::as_str), Some("1"));
    assert_eq!(client.quic.idle_timeout.as_deref(), Some("30s"));
    assert_eq!(client.quic.max_concurrent_streams, Some(128));
    assert!(client.quic.disable_path_mtu_discovery);
    assert_eq!(
        client.tls.as_ref().and_then(|t| t.server_name.as_deref()),
        Some("example.com")
    );
}

#[test]
fn test_parse_rule_set_http_client_inline_and_tag() {
    let json = r#"{
        "route": {
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "rs1",
                    "url": "https://example.com/rs.srs",
                    "http_client": "shared-client"
                },
                {
                    "type": "remote",
                    "tag": "rs2",
                    "url": "https://example.com/rs2.srs",
                    "http_client": {
                        "engine": "go",
                        "idle_timeout": "1m"
                    }
                }
            ]
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let route = config.route.unwrap();
    assert_eq!(route.rule_set.len(), 2);
    match &route.rule_set[0] {
        RuleSet::Remote(r) => match r.http_client.as_ref().unwrap() {
            HttpClientRef::Tag(t) => assert_eq!(t, "shared-client"),
            _ => panic!("expected tag reference"),
        },
        _ => panic!("expected remote rule set"),
    }
    match &route.rule_set[1] {
        RuleSet::Remote(r) => match r.http_client.as_ref().unwrap() {
            HttpClientRef::Inline(client) => {
                assert_eq!(client.engine.as_deref(), Some("go"));
                assert_eq!(client.quic.idle_timeout.as_deref(), Some("1m"));
            }
            _ => panic!("expected inline client"),
        },
        _ => panic!("expected remote rule set"),
    }
}

#[test]
fn test_parse_route_default_http_client() {
    let json = r#"{
        "route": {
            "default_http_client": "shared-client"
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let route = config.route.unwrap();
    assert_eq!(route.default_http_client.as_deref(), Some("shared-client"));
}

#[test]
fn test_parse_tls_spoof_and_engine() {
    let json = r#"{
        "type": "trojan",
        "tag": "t",
        "server": "example.com",
        "server_port": 443,
        "password": "pw",
        "tls": {
            "enabled": true,
            "server_name": "example.com",
            "engine": "apple",
            "spoof": "www.bing.com",
            "spoof_method": "sni"
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Trojan(t) => {
            let tls = t.tls.unwrap();
            assert_eq!(tls.engine.as_deref(), Some("apple"));
            assert_eq!(tls.spoof.as_deref(), Some("www.bing.com"));
            assert_eq!(tls.spoof_method.as_deref(), Some("sni"));
        }
        other => panic!("expected trojan outbound, got {other:?}"),
    }
}

#[test]
fn test_parse_hysteria_quic_fields_on_outbound() {
    let json = r#"{
        "type": "hysteria",
        "tag": "hy",
        "server": "example.com",
        "server_port": 443,
        "auth_str": "pw",
        "up_mbps": 100,
        "down_mbps": 100,
        "stream_receive_window": "8MB",
        "connection_receive_window": "64MB",
        "disable_path_mtu_discovery": true,
        "keep_alive_period": "15s",
        "max_concurrent_streams": 64,
        "initial_packet_size": 1200
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Hysteria(h) => {
            assert_eq!(h.quic.stream_receive_window.as_deref(), Some("8MB"));
            assert_eq!(h.quic.connection_receive_window.as_deref(), Some("64MB"));
            assert!(h.quic.disable_path_mtu_discovery);
            assert_eq!(h.quic.keep_alive_period.as_deref(), Some("15s"));
            assert_eq!(h.quic.max_concurrent_streams, Some(64));
            assert_eq!(h.quic.initial_packet_size, Some(1200));
        }
        other => panic!("expected hysteria outbound, got {other:?}"),
    }
}

#[test]
fn test_parse_tuic_quic_fields_on_outbound() {
    let json = r#"{
        "type": "tuic",
        "tag": "tu",
        "server": "example.com",
        "server_port": 443,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "pw",
        "idle_timeout": "30s",
        "keep_alive_period": "10s"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Tuic(t) => {
            assert_eq!(t.quic.idle_timeout.as_deref(), Some("30s"));
            assert_eq!(t.quic.keep_alive_period.as_deref(), Some("10s"));
        }
        other => panic!("expected tuic outbound, got {other:?}"),
    }
}

#[test]
fn test_parse_hysteria2_quic_fields_on_inbound() {
    let json = r#"{
        "type": "hysteria2",
        "tag": "h2in",
        "listen": "::",
        "listen_port": 443,
        "stream_receive_window": "8MB",
        "connection_receive_window": "64MB",
        "disable_path_mtu_discovery": true
    }"#;
    let inbound: Inbound = serde_json::from_str(json).unwrap();
    match inbound {
        Inbound::Hysteria2(h) => {
            assert_eq!(h.quic.stream_receive_window.as_deref(), Some("8MB"));
            assert_eq!(h.quic.connection_receive_window.as_deref(), Some("64MB"));
            assert!(h.quic.disable_path_mtu_discovery);
        }
        other => panic!("expected hysteria2 inbound, got {other:?}"),
    }
}

#[test]
fn test_parse_certificate_provider_http_client() {
    let json = r#"{
        "certificate_providers": [
            {
                "type": "tailscale",
                "tag": "ts-cert",
                "endpoint": "ts",
                "http_client": "shared"
            }
        ]
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.certificate_providers.len(), 1);
    match &config.certificate_providers[0] {
        CertificateProvider::Tailscale(p) => match p.http_client.as_ref().unwrap() {
            HttpClientRef::Tag(t) => assert_eq!(t, "shared"),
            _ => panic!("expected tag ref"),
        },
        _ => panic!("expected tailscale provider"),
    }
}

#[test]
fn test_parse_tailscale_dns_accept_search_domain() {
    let json = r#"{
        "dns": {
            "servers": [
                {"type": "tailscale", "tag": "ts", "endpoint": "ts", "accept_search_domain": true}
            ]
        }
    }"#;
    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let server = &config.dns.unwrap().servers[0];
    match server {
        turntable::config::dns::DnsServer::Tailscale(ts) => {
            assert!(ts.accept_search_domain);
        }
        _ => panic!("expected tailscale server"),
    }
}

#[test]
fn test_validation_warns_on_114_features_for_older_target() {
    use turntable::config::validation::ConfigWarning;

    let json = r#"{
        "http_clients": [{"tag": "c", "engine": "apple"}],
        "route": {
            "default_http_client": "c",
            "rule_set": [
                {"type": "remote", "tag": "r", "url": "https://example.com/r", "http_client": "c"}
            ]
        },
        "dns": {
            "servers": [
                {"type": "tailscale", "tag": "ts", "endpoint": "ts", "accept_search_domain": true}
            ]
        },
        "certificate_providers": [
            {"type": "tailscale", "tag": "cp", "endpoint": "ts", "http_client": "c"}
        ],
        "outbounds": [
            {
                "type": "trojan",
                "tag": "t",
                "server": "example.com",
                "server_port": 443,
                "password": "pw",
                "tls": {"enabled": true, "spoof": "www.bing.com", "engine": "apple"}
            },
            {
                "type": "tuic",
                "tag": "tu",
                "server": "example.com",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "password": "pw",
                "idle_timeout": "30s"
            }
        ]
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let report = config.validate_for_version(&SingBoxVersion::new(1, 13));

    let features: Vec<String> = report
        .warnings
        .iter()
        .filter_map(|w| match w {
            ConfigWarning::UnsupportedFeature { feature, .. } => Some(feature.clone()),
            _ => None,
        })
        .collect();

    assert!(features.iter().any(|f| f == "http_clients"));
    assert!(features.iter().any(|f| f == "route.default_http_client"));
    assert!(features.iter().any(|f| f.contains("accept_search_domain")));
    assert!(features.iter().any(|f| f == "certificate_provider.http_client"));
    assert!(features.iter().any(|f| f.contains("http_client") && f.contains("rule_set")));
    assert!(features.iter().any(|f| f.contains("tls.spoof")));
    assert!(features.iter().any(|f| f.contains("tls.engine")));
    assert!(features.iter().any(|f| f.contains("tuic") && f.contains("QUIC tuning")));
}

#[test]
fn test_validation_warns_on_deprecated_hysteria_tuning_for_114() {
    use turntable::config::validation::ConfigWarning;

    let json = r#"{
        "outbounds": [
            {
                "type": "hysteria",
                "tag": "hy",
                "server": "example.com",
                "server_port": 443,
                "auth_str": "pw",
                "recv_window_conn": 16777216,
                "recv_window": 67108864,
                "disable_mtu_discovery": true
            }
        ],
        "route": {
            "rule_set": [
                {"type": "remote", "tag": "r", "url": "https://example.com/r", "download_detour": "direct"}
            ]
        }
    }"#;

    let config: SingBoxConfig = serde_json::from_str(json).unwrap();
    let report = config.validate_for_version(&SingBoxVersion::new(1, 14));
    let features: Vec<String> = report
        .warnings
        .iter()
        .filter_map(|w| match w {
            ConfigWarning::DeprecatedFeature { feature, .. } => Some(feature.clone()),
            _ => None,
        })
        .collect();

    assert!(features.iter().any(|f| f.contains("legacy QUIC tuning")));
    assert!(features.iter().any(|f| f.contains("download_detour")));
}

#[test]
fn test_builder_http_client() {
    let config = SingBoxConfig::builder()
        .http_client(HttpClient {
            tag: "primary".to_string(),
            ..Default::default()
        })
        .build();
    assert_eq!(config.http_clients.len(), 1);
    assert_eq!(config.http_clients[0].tag, "primary");
}

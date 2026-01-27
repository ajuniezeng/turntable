use serde::{Deserialize, Serialize};

use crate::config::certificate::Certificate;
use crate::config::dns::Dns;
use crate::config::endpoint::Endpoint;
use crate::config::experimental::Experimental;
use crate::config::inbound::Inbound;
use crate::config::log::Log;
use crate::config::ntp::Ntp;
use crate::config::outbound::Outbound;
use crate::config::route::Route;
use crate::config::service::Service;

pub mod certificate;
pub mod dns;
pub mod endpoint;
pub mod experimental;
pub mod inbound;
pub mod log;
pub mod ntp;
pub mod outbound;
pub mod route;
pub mod service;
pub mod shared;
pub mod util;
pub mod validation;
pub mod version;

/// Main sing-box configuration structure
///
/// This struct represents the complete sing-box configuration file format.
/// All fields are optional and will be omitted from serialization if not set
/// or if set to their default values.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SingBoxConfig {
    /// Log configuration
    #[serde(default, skip_serializing_if = "is_default_log")]
    pub log: Log,

    /// DNS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,

    /// NTP configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Ntp>,

    /// Certificate configuration (since 1.12.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Certificate>,

    /// Endpoint configurations (since 1.11.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,

    /// Inbound configurations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,

    /// Outbound configurations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,

    /// Route configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<Route>,

    /// Service configurations (since 1.12.0)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,

    /// Experimental features configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}

fn is_default_log(log: &Log) -> bool {
    !log.disabled && log.level.is_none() && log.output.is_none() && log.timestamp.is_none()
}

impl SingBoxConfig {
    /// Create a new empty configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration builder
    pub fn builder() -> SingBoxConfigBuilder {
        SingBoxConfigBuilder::new()
    }

    /// Serialize the configuration to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the configuration to a pretty-printed JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a configuration from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Builder for SingBoxConfig
#[derive(Default)]
pub struct SingBoxConfigBuilder {
    config: SingBoxConfig,
}

impl SingBoxConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set log configuration
    pub fn log(mut self, log: Log) -> Self {
        self.config.log = log;
        self
    }

    /// Set DNS configuration
    pub fn dns(mut self, dns: Dns) -> Self {
        self.config.dns = Some(dns);
        self
    }

    /// Set NTP configuration
    pub fn ntp(mut self, ntp: Ntp) -> Self {
        self.config.ntp = Some(ntp);
        self
    }

    /// Set certificate configuration
    pub fn certificate(mut self, certificate: Certificate) -> Self {
        self.config.certificate = Some(certificate);
        self
    }

    /// Add an endpoint
    pub fn endpoint(mut self, endpoint: Endpoint) -> Self {
        self.config.endpoints.push(endpoint);
        self
    }

    /// Set endpoints
    pub fn endpoints(mut self, endpoints: Vec<Endpoint>) -> Self {
        self.config.endpoints = endpoints;
        self
    }

    /// Add an inbound
    pub fn inbound(mut self, inbound: Inbound) -> Self {
        self.config.inbounds.push(inbound);
        self
    }

    /// Set inbounds
    pub fn inbounds(mut self, inbounds: Vec<Inbound>) -> Self {
        self.config.inbounds = inbounds;
        self
    }

    /// Add an outbound
    pub fn outbound(mut self, outbound: Outbound) -> Self {
        self.config.outbounds.push(outbound);
        self
    }

    /// Set outbounds
    pub fn outbounds(mut self, outbounds: Vec<Outbound>) -> Self {
        self.config.outbounds = outbounds;
        self
    }

    /// Set route configuration
    pub fn route(mut self, route: Route) -> Self {
        self.config.route = Some(route);
        self
    }

    /// Add a service
    pub fn service(mut self, service: Service) -> Self {
        self.config.services.push(service);
        self
    }

    /// Set services
    pub fn services(mut self, services: Vec<Service>) -> Self {
        self.config.services = services;
        self
    }

    /// Set experimental configuration
    pub fn experimental(mut self, experimental: Experimental) -> Self {
        self.config.experimental = Some(experimental);
        self
    }

    /// Build the configuration
    pub fn build(self) -> SingBoxConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::endpoint::{TailscaleEndpoint, WireGuardEndpoint, WireGuardPeer};
    use crate::config::inbound::{MixedInbound, SocksInbound, TunInbound};
    use crate::config::log::LogLevel;
    use crate::config::outbound::{BlockOutbound, DirectOutbound, SelectorOutbound, SocksOutbound};
    use crate::config::route::{RouteAction, RouteRule, RuleAction};
    use crate::config::service::{CcmService, ResolvedService};

    #[test]
    fn test_singbox_config_default_serializes_empty() {
        let config = SingBoxConfig::default();
        let json = config.to_json().unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_singbox_config_with_log() {
        let config = SingBoxConfig {
            log: Log {
                disabled: false,
                level: Some(LogLevel::Debug),
                output: Some("box.log".to_string()),
                timestamp: Some(true),
            },
            ..Default::default()
        };
        let json = config.to_json().unwrap();
        assert!(json.contains(r#""level":"debug""#));
        assert!(json.contains(r#""output":"box.log""#));
        assert!(json.contains(r#""timestamp":true"#));
    }

    #[test]
    fn test_singbox_config_builder() {
        let config = SingBoxConfig::builder()
            .log(Log {
                level: Some(LogLevel::Info),
                ..Default::default()
            })
            .build();

        let json = config.to_json().unwrap();
        assert!(json.contains(r#""level":"info""#));
    }

    #[test]
    fn test_singbox_config_roundtrip() {
        let original = SingBoxConfig {
            log: Log {
                level: Some(LogLevel::Warn),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = original.to_json_pretty().unwrap();
        let parsed = SingBoxConfig::from_json(&json).unwrap();
        assert_eq!(parsed.log.level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_singbox_config_full_structure() {
        let json = r#"{
            "log": {"level": "info"},
            "dns": {"final": "local"},
            "ntp": {"enabled": true, "server": "time.apple.com"},
            "certificate": {"store": "mozilla"},
            "experimental": {
                "cache_file": {"enabled": true}
            }
        }"#;
        let config: SingBoxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.log.level, Some(LogLevel::Info));
        assert!(config.dns.is_some());
        assert!(config.ntp.is_some());
        assert!(config.certificate.is_some());
        assert!(config.experimental.is_some());
    }

    #[test]
    fn test_singbox_config_with_outbounds() {
        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .build();

        assert_eq!(config.outbounds.len(), 2);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("direct"));
        assert!(json.contains("block"));
    }

    #[test]
    fn test_singbox_config_with_wireguard_endpoint() {
        let peer = WireGuardPeer::new("public_key==", vec!["0.0.0.0/0".to_string()])
            .with_address("1.2.3.4", 51820);

        let wg = WireGuardEndpoint::new("wg-ep", "private_key==", vec!["10.0.0.1/24".to_string()])
            .add_peer(peer);

        let config = SingBoxConfig::builder()
            .endpoint(Endpoint::WireGuard(wg))
            .build();

        assert_eq!(config.endpoints.len(), 1);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("wireguard"));
        assert!(json.contains("wg-ep"));
    }

    #[test]
    fn test_singbox_config_with_tailscale_endpoint() {
        let ts = TailscaleEndpoint::new("ts-ep")
            .with_hostname("my-node")
            .with_auth_key("tskey-xxx");

        let config = SingBoxConfig::builder()
            .endpoint(Endpoint::Tailscale(ts))
            .build();

        assert_eq!(config.endpoints.len(), 1);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("tailscale"));
        assert!(json.contains("ts-ep"));
        assert!(json.contains("my-node"));
    }

    #[test]
    fn test_singbox_config_with_multiple_endpoints() {
        let wg = WireGuardEndpoint::new("wg-ep", "key==", vec!["10.0.0.1/24".to_string()]);
        let ts = TailscaleEndpoint::new("ts-ep");

        let config = SingBoxConfig::builder()
            .endpoint(Endpoint::WireGuard(wg))
            .endpoint(Endpoint::Tailscale(ts))
            .build();

        assert_eq!(config.endpoints.len(), 2);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("wireguard"));
        assert!(json.contains("tailscale"));
    }

    #[test]
    fn test_singbox_config_with_inbounds() {
        let mixed = MixedInbound::new("mixed-in").listen("127.0.0.1", 7890);
        let socks = SocksInbound::new("socks-in").listen("127.0.0.1", 1080);

        let config = SingBoxConfig::builder()
            .inbound(Inbound::Mixed(mixed))
            .inbound(Inbound::Socks(socks))
            .build();

        assert_eq!(config.inbounds.len(), 2);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("mixed"));
        assert!(json.contains("socks"));
    }

    #[test]
    fn test_singbox_config_with_tun_inbound() {
        let tun = TunInbound::new("tun-in")
            .address(vec!["172.18.0.1/30".to_string()])
            .auto_route()
            .stack("system");

        let config = SingBoxConfig::builder().inbound(Inbound::Tun(tun)).build();

        assert_eq!(config.inbounds.len(), 1);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("tun"));
        assert!(json.contains("auto_route"));
    }

    #[test]
    fn test_singbox_config_with_selector_outbound() {
        let direct = DirectOutbound::new("direct");
        let proxy = SocksOutbound::new("proxy", "127.0.0.1", 1080);
        let selector =
            SelectorOutbound::new("select", vec!["direct".to_string(), "proxy".to_string()])
                .with_default("direct");

        let config = SingBoxConfig::builder()
            .outbound(Outbound::Direct(direct))
            .outbound(Outbound::Socks(proxy))
            .outbound(Outbound::Selector(selector))
            .build();

        assert_eq!(config.outbounds.len(), 3);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("selector"));
        assert!(
            json.contains("\"default\": \"direct\"") || json.contains("\"default\":\"direct\"")
        );
    }

    #[test]
    fn test_singbox_config_full_example() {
        let config = SingBoxConfig::builder()
            .log(Log {
                level: Some(LogLevel::Info),
                ..Default::default()
            })
            .inbound(Inbound::Mixed(
                MixedInbound::new("mixed-in").listen("127.0.0.1", 7890),
            ))
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .build();

        let json = config.to_json_pretty().unwrap();
        // Pretty-printed JSON has spaces after colons
        assert!(json.contains("\"level\": \"info\"") || json.contains("\"level\":\"info\""));
        assert!(json.contains("\"type\": \"mixed\"") || json.contains("\"type\":\"mixed\""));
        assert!(json.contains("\"type\": \"direct\"") || json.contains("\"type\":\"direct\""));
        assert!(json.contains("\"type\": \"block\"") || json.contains("\"type\":\"block\""));
    }

    #[test]
    fn test_singbox_config_with_route() {
        let route = Route::new()
            .with_final("direct")
            .with_auto_detect_interface()
            .add_rule(
                RouteRule::new()
                    .match_domain_suffix(vec![".cn".to_string()])
                    .with_action(RuleAction::Route(RouteAction::new("direct"))),
            );

        let config = SingBoxConfig::builder()
            .route(route)
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .build();

        assert!(config.route.is_some());
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("auto_detect_interface"));
        assert!(json.contains(".cn"));
    }

    #[test]
    fn test_singbox_config_with_services() {
        let ccm = Service::Ccm(Box::new(
            CcmService::new("127.0.0.1", 8080)
                .with_tag("ccm")
                .add_user("alice", "token-a"),
        ));
        let resolved = Service::Resolved(Box::new(ResolvedService::new().with_tag("resolved")));

        let config = SingBoxConfig::builder()
            .service(ccm)
            .service(resolved)
            .build();

        assert_eq!(config.services.len(), 2);
        let json = config.to_json_pretty().unwrap();
        assert!(json.contains("ccm"));
        assert!(json.contains("resolved"));
    }

    #[test]
    fn test_singbox_config_complete() {
        // Test a complete configuration with all major components
        let config = SingBoxConfig::builder()
            .log(Log {
                level: Some(LogLevel::Info),
                ..Default::default()
            })
            .inbound(Inbound::Mixed(
                MixedInbound::new("mixed-in").listen("127.0.0.1", 7890),
            ))
            .outbound(Outbound::Direct(DirectOutbound::new("direct")))
            .outbound(Outbound::Block(BlockOutbound::new("block")))
            .route(
                Route::new().with_final("direct").add_rule(
                    RouteRule::new()
                        .match_protocol(vec!["dns".to_string()])
                        .with_action(RuleAction::HijackDns),
                ),
            )
            .service(Service::Resolved(Box::new(ResolvedService::new())))
            .build();

        let json = config.to_json_pretty().unwrap();
        let parsed: SingBoxConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.log.level, Some(LogLevel::Info));
        assert_eq!(parsed.inbounds.len(), 1);
        assert_eq!(parsed.outbounds.len(), 2);
        assert!(parsed.route.is_some());
        assert_eq!(parsed.services.len(), 1);
    }
}

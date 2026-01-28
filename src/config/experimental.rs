use serde::{Deserialize, Serialize};

use crate::config::serde_helpers::is_false;

/// Experimental features configuration for sing-box
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Experimental {
    /// Cache file configuration (since 1.8.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFile>,

    /// Clash API configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApi>,

    /// V2Ray API configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_api: Option<V2RayApi>,
}

/// Cache file configuration (since 1.8.0)
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CacheFile {
    /// Enable cache file
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Path to the cache file (default: "cache.db")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Identifier in the cache file
    /// If not empty, configuration specified data will use a separate store keyed by it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,

    /// Store FakeIP in the cache file
    #[serde(default, skip_serializing_if = "is_false")]
    pub store_fakeip: bool,

    /// Store rejected DNS response cache in the cache file (since 1.9.0)
    #[serde(default, skip_serializing_if = "is_false")]
    pub store_rdrc: bool,

    /// Timeout of rejected DNS response cache (default: "7d", since 1.9.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdrc_timeout: Option<String>,
}

/// Clash API configuration
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ClashApi {
    /// RESTful web API listening address
    /// Clash API will be disabled if empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_controller: Option<String>,

    /// Relative path to configuration directory or absolute path for static web resources
    /// sing-box will serve it at `http://{{external-controller}}/ui`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui: Option<String>,

    /// ZIP download URL for the external UI
    /// Used if the specified external_ui directory is empty
    /// Default: "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui_download_url: Option<String>,

    /// The tag of the outbound to download the external UI
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ui_download_detour: Option<String>,

    /// Secret for the RESTful API (optional)
    /// Authenticate by specifying HTTP header `Authorization: Bearer ${secret}`
    /// ALWAYS set a secret if RESTful API is listening on 0.0.0.0
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Default mode in Clash (default: "Rule")
    /// This setting has no direct effect, but can be used in routing and DNS rules
    /// via the `clash_mode` rule item
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,

    /// CORS allowed origins (since 1.10.0)
    /// `*` will be used if empty
    /// To access the Clash API on a private network from a public website,
    /// you must explicitly specify it instead of using `*`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_control_allow_origin: Vec<String>,

    /// Allow access from private network (since 1.10.0)
    /// Required to access the Clash API on a private network from a public website
    #[serde(default, skip_serializing_if = "is_false")]
    pub access_control_allow_private_network: bool,

    // Deprecated fields (deprecated in 1.8.0)
    /// Deprecated: Use cache_file.enabled instead
    #[serde(default, skip_serializing_if = "is_false")]
    pub store_mode: bool,

    /// Deprecated: Use cache_file.enabled instead
    #[serde(default, skip_serializing_if = "is_false")]
    pub store_selected: bool,

    /// Deprecated: Use cache_file.store_fakeip instead
    #[serde(default, skip_serializing_if = "is_false")]
    pub store_fakeip: bool,

    /// Deprecated: Use cache_file.enabled and cache_file.path instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<String>,

    /// Deprecated: Use cache_file.cache_id instead
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,
}

/// V2Ray API configuration
/// Note: V2Ray API is not included by default, requires build tag
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct V2RayApi {
    /// gRPC API listening address
    /// V2Ray API will be disabled if empty
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Traffic statistics service settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<V2RayStats>,
}

/// V2Ray statistics service settings
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct V2RayStats {
    /// Enable statistics service
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,

    /// Inbound list to count traffic
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<String>,

    /// Outbound list to count traffic
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<String>,

    /// User list to count traffic
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_experimental_default_serializes_empty() {
        let exp = Experimental::default();
        let json = serde_json::to_string(&exp).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_cache_file_basic() {
        let cache = CacheFile {
            enabled: true,
            path: Some("cache.db".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&cache).unwrap();
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""path":"cache.db""#));
    }

    #[test]
    fn test_cache_file_with_rdrc() {
        let cache = CacheFile {
            enabled: true,
            store_rdrc: true,
            rdrc_timeout: Some("7d".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&cache).unwrap();
        assert!(json.contains(r#""store_rdrc":true"#));
        assert!(json.contains(r#""rdrc_timeout":"7d""#));
    }

    #[test]
    fn test_clash_api_basic() {
        let clash = ClashApi {
            external_controller: Some("127.0.0.1:9090".to_string()),
            secret: Some("my-secret".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&clash).unwrap();
        assert!(json.contains(r#""external_controller":"127.0.0.1:9090""#));
        assert!(json.contains(r#""secret":"my-secret""#));
    }

    #[test]
    fn test_clash_api_with_external_ui() {
        let clash = ClashApi {
            external_controller: Some("127.0.0.1:9090".to_string()),
            external_ui: Some("dashboard".to_string()),
            external_ui_download_url: Some(
                "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip".to_string(),
            ),
            ..Default::default()
        };
        let json = serde_json::to_string(&clash).unwrap();
        assert!(json.contains(r#""external_ui":"dashboard""#));
        assert!(json.contains("Yacd-meta"));
    }

    #[test]
    fn test_clash_api_with_cors() {
        let clash = ClashApi {
            external_controller: Some("127.0.0.1:9090".to_string()),
            access_control_allow_origin: vec![
                "http://127.0.0.1".to_string(),
                "http://yacd.haishan.me".to_string(),
            ],
            access_control_allow_private_network: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&clash).unwrap();
        assert!(json.contains("access_control_allow_origin"));
        assert!(json.contains("yacd.haishan.me"));
        assert!(json.contains(r#""access_control_allow_private_network":true"#));
    }

    #[test]
    fn test_v2ray_api_basic() {
        let v2ray = V2RayApi {
            listen: Some("127.0.0.1:8080".to_string()),
            stats: Some(V2RayStats {
                enabled: true,
                inbounds: vec!["socks-in".to_string()],
                outbounds: vec!["proxy".to_string(), "direct".to_string()],
                users: vec!["sekai".to_string()],
            }),
        };
        let json = serde_json::to_string(&v2ray).unwrap();
        assert!(json.contains(r#""listen":"127.0.0.1:8080""#));
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains("socks-in"));
        assert!(json.contains("proxy"));
        assert!(json.contains("sekai"));
    }

    #[test]
    fn test_experimental_full_config() {
        let exp = Experimental {
            cache_file: Some(CacheFile {
                enabled: true,
                store_fakeip: true,
                ..Default::default()
            }),
            clash_api: Some(ClashApi {
                external_controller: Some("127.0.0.1:9090".to_string()),
                ..Default::default()
            }),
            v2ray_api: Some(V2RayApi {
                listen: Some("127.0.0.1:8080".to_string()),
                ..Default::default()
            }),
        };
        let json = serde_json::to_string_pretty(&exp).unwrap();
        assert!(json.contains("cache_file"));
        assert!(json.contains("clash_api"));
        assert!(json.contains("v2ray_api"));
    }

    #[test]
    fn test_experimental_deserialization() {
        let json = r#"{
            "cache_file": {
                "enabled": true,
                "path": "my-cache.db"
            },
            "clash_api": {
                "external_controller": "0.0.0.0:9090",
                "secret": "test-secret"
            }
        }"#;
        let exp: Experimental = serde_json::from_str(json).unwrap();
        assert!(exp.cache_file.is_some());
        let cache = exp.cache_file.unwrap();
        assert!(cache.enabled);
        assert_eq!(cache.path, Some("my-cache.db".to_string()));

        assert!(exp.clash_api.is_some());
        let clash = exp.clash_api.unwrap();
        assert_eq!(clash.external_controller, Some("0.0.0.0:9090".to_string()));
        assert_eq!(clash.secret, Some("test-secret".to_string()));
    }
}

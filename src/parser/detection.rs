//! Subscription format detection
//!
//! This module provides functionality for detecting the type of subscription
//! content, including Sing-box JSON, Base64 URI lists, plain URI lists, and
//! Clash YAML formats.

use tracing::debug;

use super::base64::decode_base64;

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
pub fn is_singbox_json(content: &str) -> bool {
    // Must start with { and be valid-ish JSON with "outbounds"
    let trimmed = content.trim();
    if !trimmed.starts_with('{') {
        return false;
    }

    // Quick check for "outbounds" key
    trimmed.contains("\"outbounds\"")
}

/// Checks if content is Clash YAML format
pub fn is_clash_yaml(content: &str) -> bool {
    let trimmed = content.trim();

    // Clash configs typically start with these keys
    trimmed.starts_with("proxies:")
        || trimmed.starts_with("proxy-groups:")
        || trimmed.starts_with("port:")
        || (trimmed.contains("proxies:") && trimmed.contains("- name:"))
}

/// Checks if content is a plain URI list
pub fn is_plain_uri_list(content: &str) -> bool {
    let first_line = content.lines().next().unwrap_or("").trim();

    // Check if first line looks like a proxy URI
    is_proxy_uri(first_line)
}

/// Checks if a string looks like a proxy URI
pub fn is_proxy_uri(s: &str) -> bool {
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
pub fn is_base64_content(content: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_singbox_json() {
        let content = r#"{"outbounds": []}"#;
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::SingBoxJson
        );
    }

    #[test]
    fn test_detect_singbox_json_with_whitespace() {
        let content = r#"
        {
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ]
        }
        "#;
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::SingBoxJson
        );
    }

    #[test]
    fn test_detect_plain_uri_list() {
        let content = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#tag\nvmess://...";
        assert_eq!(
            detect_subscription_type(content),
            SubscriptionType::PlainUriList
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

    #[test]
    fn test_is_singbox_json_valid() {
        assert!(is_singbox_json(r#"{"outbounds": []}"#));
        assert!(is_singbox_json(r#"  { "outbounds": [] }  "#));
    }

    #[test]
    fn test_is_singbox_json_invalid() {
        assert!(!is_singbox_json("not json"));
        assert!(!is_singbox_json(r#"{"other": []}"#));
        assert!(!is_singbox_json(""));
    }

    #[test]
    fn test_is_clash_yaml_valid() {
        assert!(is_clash_yaml("proxies:"));
        assert!(is_clash_yaml("proxy-groups:"));
        assert!(is_clash_yaml("port: 7890"));
        assert!(is_clash_yaml("mixed:\nproxies:\n  - name: test"));
    }

    #[test]
    fn test_is_clash_yaml_invalid() {
        assert!(!is_clash_yaml("not yaml"));
        assert!(!is_clash_yaml(r#"{"json": true}"#));
    }

    #[test]
    fn test_is_proxy_uri_valid() {
        assert!(is_proxy_uri("ss://abc"));
        assert!(is_proxy_uri("vmess://xyz"));
        assert!(is_proxy_uri("vless://uuid@host:port"));
        assert!(is_proxy_uri("trojan://password@host:port"));
        assert!(is_proxy_uri("hysteria2://auth@host:port"));
        assert!(is_proxy_uri("hy2://auth@host:port"));
        assert!(is_proxy_uri("tuic://uuid:password@host:port"));
    }

    #[test]
    fn test_is_proxy_uri_invalid() {
        assert!(!is_proxy_uri("not a uri"));
        assert!(!is_proxy_uri("ftp://example.com"));
        assert!(!is_proxy_uri(""));
    }

    #[test]
    fn test_is_plain_uri_list_valid() {
        assert!(is_plain_uri_list("ss://abc\nss://def"));
        assert!(is_plain_uri_list("vmess://xyz"));
    }

    #[test]
    fn test_is_plain_uri_list_invalid() {
        assert!(!is_plain_uri_list("not a uri list"));
        assert!(!is_plain_uri_list(""));
    }

    #[test]
    fn test_subscription_type_display() {
        assert_eq!(
            format!("{}", SubscriptionType::SingBoxJson),
            "Sing-box JSON"
        );
        assert_eq!(
            format!("{}", SubscriptionType::Base64UriList),
            "Base64 URI List"
        );
        assert_eq!(
            format!("{}", SubscriptionType::PlainUriList),
            "Plain URI List"
        );
        assert_eq!(format!("{}", SubscriptionType::ClashYaml), "Clash YAML");
        assert_eq!(format!("{}", SubscriptionType::Unknown), "Unknown");
    }
}

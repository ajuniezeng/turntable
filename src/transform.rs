//! Configuration transformation utilities
//!
//! This module provides functionality for transforming sing-box configurations:
//! - IPv6 outbound filtering
//! - Country code extraction from flag emojis
//! - Selector generation (country-based and subscription-based)

use std::collections::HashMap;
use std::net::Ipv6Addr;

use tracing::{debug, info};

use crate::config::outbound::{Outbound, SelectorOutbound};

// ============================================================================
// IPv6 Filtering
// ============================================================================

/// Get the server address from an outbound, if applicable.
pub fn get_outbound_server(outbound: &Outbound) -> Option<&str> {
    match outbound {
        Outbound::Socks(o) => o.server.as_deref(),
        Outbound::Http(o) => o.server.as_deref(),
        Outbound::Shadowsocks(o) => o.server.as_deref(),
        Outbound::VMess(o) => o.server.as_deref(),
        Outbound::Trojan(o) => o.server.as_deref(),
        Outbound::WireGuard(o) => o.server.as_deref(),
        Outbound::Hysteria(o) => o.server.as_deref(),
        Outbound::VLess(o) => o.server.as_deref(),
        Outbound::ShadowTls(o) => o.server.as_deref(),
        Outbound::Tuic(o) => o.server.as_deref(),
        Outbound::Hysteria2(o) => o.server.as_deref(),
        Outbound::AnyTls(o) => o.server.as_deref(),
        Outbound::Ssh(o) => o.server.as_deref(),
        Outbound::Naive(o) => o.server.as_deref(),
        // These don't have server fields
        Outbound::Direct(_)
        | Outbound::Block(_)
        | Outbound::Dns(_)
        | Outbound::Selector(_)
        | Outbound::UrlTest(_)
        | Outbound::Tor(_) => None,
    }
}

/// Check if a server address is an IPv6 address.
///
/// Handles both raw IPv6 addresses (e.g., "::1", "2001:db8::1")
/// and bracketed IPv6 addresses (e.g., "[::1]", "[2001:db8::1]").
pub fn is_ipv6_address(server: &str) -> bool {
    // Remove brackets if present (common in URLs)
    let addr = server.trim_start_matches('[').trim_end_matches(']');

    // Try to parse as IPv6
    addr.parse::<Ipv6Addr>().is_ok()
}

/// Filter out outbounds that have IPv6 server addresses.
///
/// Returns a new vector containing only outbounds with IPv4 or hostname servers.
pub fn filter_ipv6_outbounds(outbounds: Vec<Outbound>) -> Vec<Outbound> {
    let original_count = outbounds.len();
    let filtered: Vec<Outbound> = outbounds
        .into_iter()
        .filter(|outbound| {
            if let Some(server) = get_outbound_server(outbound)
                && is_ipv6_address(server)
            {
                debug!("Filtering out IPv6 outbound: server={}", server);
                return false;
            }
            true
        })
        .collect();

    let removed_count = original_count - filtered.len();
    if removed_count > 0 {
        info!("Filtered out {} IPv6 outbounds", removed_count);
    }

    filtered
}

// ============================================================================
// Country Code Extraction
// ============================================================================

/// Extract a country code from a flag emoji in a string.
///
/// Flag emojis are composed of two Regional Indicator Symbols.
/// For example, 🇺🇸 (US flag) = 🇺 (U+1F1FA) + 🇸 (U+1F1F8)
///
/// Regional Indicator Symbols range from U+1F1E6 (🇦 for A) to U+1F1FF (🇿 for Z).
///
/// Returns the two-letter ISO 3166-1 alpha-2 country code if found.
pub fn extract_country_code(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();

    for i in 0..chars.len().saturating_sub(1) {
        let c1 = chars[i];
        let c2 = chars[i + 1];

        // Check if both characters are Regional Indicator Symbols
        if is_regional_indicator(c1) && is_regional_indicator(c2) {
            let letter1 = regional_indicator_to_letter(c1)?;
            let letter2 = regional_indicator_to_letter(c2)?;
            return Some(format!("{}{}", letter1, letter2));
        }
    }

    None
}

/// Check if a character is a Regional Indicator Symbol (U+1F1E6 to U+1F1FF).
fn is_regional_indicator(c: char) -> bool {
    let code = c as u32;
    (0x1F1E6..=0x1F1FF).contains(&code)
}

/// Convert a Regional Indicator Symbol to its corresponding letter (A-Z).
fn regional_indicator_to_letter(c: char) -> Option<char> {
    let code = c as u32;
    if (0x1F1E6..=0x1F1FF).contains(&code) {
        // U+1F1E6 corresponds to 'A', U+1F1E7 to 'B', etc.
        let letter_offset = code - 0x1F1E6;
        Some((b'A' + letter_offset as u8) as char)
    } else {
        None
    }
}

/// Convert an ASCII letter (A-Z) to its corresponding Regional Indicator Symbol.
fn letter_to_regional_indicator(c: char) -> Option<char> {
    let upper = c.to_ascii_uppercase();
    if upper.is_ascii_uppercase() {
        // 'A' corresponds to U+1F1E6, 'B' to U+1F1E7, etc.
        let code = 0x1F1E6 + (upper as u32 - 'A' as u32);
        char::from_u32(code)
    } else {
        None
    }
}

/// Convert a two-letter country code to a flag emoji.
///
/// For example, "US" becomes "🇺🇸", "JP" becomes "🇯🇵".
pub fn country_code_to_flag(code: &str) -> Option<String> {
    let chars: Vec<char> = code.chars().collect();
    if chars.len() != 2 {
        return None;
    }

    let ri1 = letter_to_regional_indicator(chars[0])?;
    let ri2 = letter_to_regional_indicator(chars[1])?;

    Some(format!("{}{}", ri1, ri2))
}

/// Format a country code with its flag emoji.
///
/// For example, "US" becomes "🇺🇸 US", "JP" becomes "🇯🇵 JP".
pub fn format_country_code_with_flag(code: &str) -> String {
    if let Some(flag) = country_code_to_flag(code) {
        format!("{} {}", flag, code)
    } else {
        code.to_string()
    }
}

/// Get the tag from an outbound.
pub fn get_outbound_tag(outbound: &Outbound) -> Option<&str> {
    match outbound {
        Outbound::Direct(o) => o.tag.as_deref(),
        Outbound::Block(o) => o.tag.as_deref(),
        Outbound::Socks(o) => o.tag.as_deref(),
        Outbound::Http(o) => o.tag.as_deref(),
        Outbound::Shadowsocks(o) => o.tag.as_deref(),
        Outbound::VMess(o) => o.tag.as_deref(),
        Outbound::Trojan(o) => o.tag.as_deref(),
        Outbound::WireGuard(o) => o.tag.as_deref(),
        Outbound::Hysteria(o) => o.tag.as_deref(),
        Outbound::VLess(o) => o.tag.as_deref(),
        Outbound::ShadowTls(o) => o.tag.as_deref(),
        Outbound::Tuic(o) => o.tag.as_deref(),
        Outbound::Hysteria2(o) => o.tag.as_deref(),
        Outbound::AnyTls(o) => o.tag.as_deref(),
        Outbound::Tor(o) => o.tag.as_deref(),
        Outbound::Ssh(o) => o.tag.as_deref(),
        Outbound::Dns(o) => o.tag.as_deref(),
        Outbound::Selector(o) => o.tag.as_deref(),
        Outbound::UrlTest(o) => o.tag.as_deref(),
        Outbound::Naive(o) => o.tag.as_deref(),
    }
}

/// Group outbounds by their country code (extracted from flag emojis in tags).
///
/// Returns a HashMap where keys are country codes and values are vectors of outbound tags.
pub fn group_outbounds_by_country(outbounds: &[Outbound]) -> HashMap<String, Vec<String>> {
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();

    for outbound in outbounds {
        if let Some(tag) = get_outbound_tag(outbound)
            && let Some(country_code) = extract_country_code(tag)
        {
            groups
                .entry(country_code)
                .or_default()
                .push(tag.to_string());
        }
    }

    groups
}

// ============================================================================
// Selector Generation
// ============================================================================

/// Generate country code selectors from outbounds.
///
/// Creates a selector outbound for each unique country code found in outbound tags.
/// The selector tag format is "🇺🇸 US" (flag + code).
///
/// Returns a vector of selector outbounds sorted by country code.
pub fn generate_country_code_selectors(outbounds: &[Outbound]) -> Vec<Outbound> {
    generate_country_code_selectors_filtered(outbounds, &[])
}

/// Generate country code selectors from outbounds, filtered by allowed country codes.
///
/// Creates a selector outbound for each unique country code found in outbound tags.
/// The selector tag format is "🇺🇸 US" (flag + code).
///
/// If `allowed_codes` is empty, all country codes found will be included.
/// Otherwise, only country codes in `allowed_codes` will be included.
///
/// Returns a vector of selector outbounds sorted by country code.
pub fn generate_country_code_selectors_filtered(
    outbounds: &[Outbound],
    allowed_codes: &[String],
) -> Vec<Outbound> {
    let groups = group_outbounds_by_country(outbounds);

    // Filter groups if allowed_codes is not empty
    let filtered_groups: HashMap<String, Vec<String>> = if allowed_codes.is_empty() {
        groups
    } else {
        // Normalize allowed codes to uppercase for comparison
        let allowed_set: std::collections::HashSet<String> =
            allowed_codes.iter().map(|c| c.to_uppercase()).collect();
        groups
            .into_iter()
            .filter(|(code, _)| allowed_set.contains(code))
            .collect()
    };

    let mut selectors: Vec<Outbound> = filtered_groups
        .into_iter()
        .map(|(country_code, outbound_tags)| {
            let tag = format_country_code_with_flag(&country_code);
            let selector = SelectorOutbound::new(tag.clone(), outbound_tags);
            debug!(
                "Generated country code selector: {} with {} outbounds",
                tag,
                selector.outbounds.len()
            );
            Outbound::Selector(selector)
        })
        .collect();

    // Sort by country code (extracted from tag) for consistent ordering
    selectors.sort_by(|a, b| {
        let tag_a = get_outbound_tag(a).unwrap_or("");
        let tag_b = get_outbound_tag(b).unwrap_or("");
        // Extract country code from "🇺🇸 US" format for sorting
        let code_a = tag_a.split_whitespace().last().unwrap_or(tag_a);
        let code_b = tag_b.split_whitespace().last().unwrap_or(tag_b);
        code_a.cmp(code_b)
    });

    info!("Generated {} country code selectors", selectors.len());
    selectors
}

/// Generate a subscription selector from outbounds.
///
/// Creates a selector outbound containing all outbounds from a subscription.
/// The selector tag is the subscription name.
pub fn generate_subscription_selector(name: &str, outbounds: &[Outbound]) -> Outbound {
    let outbound_tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
        .collect();

    debug!(
        "Generated subscription selector: {} with {} outbounds",
        name,
        outbound_tags.len()
    );

    Outbound::Selector(SelectorOutbound::new(name.to_string(), outbound_tags))
}

/// Update existing selectors in outbounds to include new selector tags.
///
/// This function modifies existing Selector and UrlTest outbounds to include
/// the provided new selector tags at the beginning of their outbounds list.
pub fn update_selectors_with_new_tags(outbounds: &mut [Outbound], new_selector_tags: &[String]) {
    if new_selector_tags.is_empty() {
        return;
    }

    for outbound in outbounds.iter_mut() {
        match outbound {
            Outbound::Selector(selector) => {
                let tag = selector
                    .tag
                    .clone()
                    .unwrap_or_else(|| "unnamed".to_string());
                // Insert new tags at the beginning
                let mut new_outbounds = new_selector_tags.to_vec();
                new_outbounds.append(&mut selector.outbounds);
                selector.outbounds = new_outbounds;
                debug!(
                    "Updated selector '{}' with {} new tags",
                    tag,
                    new_selector_tags.len()
                );
            }
            Outbound::UrlTest(urltest) => {
                let tag = urltest.tag.clone().unwrap_or_else(|| "unnamed".to_string());
                // Insert new tags at the beginning
                let mut new_outbounds = new_selector_tags.to_vec();
                new_outbounds.append(&mut urltest.outbounds);
                urltest.outbounds = new_outbounds;
                debug!(
                    "Updated urltest '{}' with {} new tags",
                    tag,
                    new_selector_tags.len()
                );
            }
            _ => {}
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::outbound::{
        DirectOutbound, ShadowsocksOutbound, SocksOutbound, UrlTestOutbound,
    };
    use std::collections::HashSet;

    // ------------------------------------------------------------------------
    // IPv6 Filtering Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_ipv6_address_simple() {
        assert!(is_ipv6_address("::1"));
        assert!(is_ipv6_address("::"));
        assert!(is_ipv6_address("2001:db8::1"));
        assert!(is_ipv6_address("fe80::1"));
        assert!(is_ipv6_address("2001:0db8:0000:0000:0000:0000:0000:0001"));
    }

    #[test]
    fn test_is_ipv6_address_bracketed() {
        assert!(is_ipv6_address("[::1]"));
        assert!(is_ipv6_address("[2001:db8::1]"));
        assert!(is_ipv6_address("[fe80::1]"));
    }

    #[test]
    fn test_is_ipv6_address_not_ipv6() {
        assert!(!is_ipv6_address("192.168.1.1"));
        assert!(!is_ipv6_address("10.0.0.1"));
        assert!(!is_ipv6_address("example.com"));
        assert!(!is_ipv6_address("my-server.example.com"));
    }

    #[test]
    fn test_filter_ipv6_outbounds() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("ipv4-proxy", "192.168.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("ipv6-proxy", "::1", 1080)),
            Outbound::Socks(SocksOutbound::new(
                "hostname-proxy",
                "proxy.example.com",
                1080,
            )),
            Outbound::Direct(DirectOutbound::new("direct")),
        ];

        let filtered = filter_ipv6_outbounds(outbounds);

        assert_eq!(filtered.len(), 3);
        let tags: Vec<_> = filtered.iter().filter_map(get_outbound_tag).collect();
        assert!(tags.contains(&"ipv4-proxy"));
        assert!(tags.contains(&"hostname-proxy"));
        assert!(tags.contains(&"direct"));
        assert!(!tags.contains(&"ipv6-proxy"));
    }

    // ------------------------------------------------------------------------
    // Country Code Extraction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_extract_country_code_us() {
        assert_eq!(extract_country_code("🇺🇸 US Server"), Some("US".to_string()));
    }

    #[test]
    fn test_extract_country_code_jp() {
        assert_eq!(
            extract_country_code("🇯🇵 Tokyo Server"),
            Some("JP".to_string())
        );
    }

    #[test]
    fn test_extract_country_code_hk() {
        assert_eq!(
            extract_country_code("🇭🇰 Hong Kong #1"),
            Some("HK".to_string())
        );
    }

    #[test]
    fn test_extract_country_code_in_middle() {
        assert_eq!(
            extract_country_code("Server 🇬🇧 London"),
            Some("GB".to_string())
        );
    }

    #[test]
    fn test_extract_country_code_multiple_flags_returns_first() {
        // Should return the first flag found
        assert_eq!(extract_country_code("🇺🇸 to 🇯🇵"), Some("US".to_string()));
    }

    #[test]
    fn test_extract_country_code_no_flag() {
        assert_eq!(extract_country_code("No flag here"), None);
        assert_eq!(extract_country_code("Just text 123"), None);
        assert_eq!(extract_country_code(""), None);
    }

    #[test]
    fn test_extract_country_code_single_regional_indicator() {
        // A single regional indicator should not match
        assert_eq!(extract_country_code("🇺 incomplete"), None);
    }

    // ------------------------------------------------------------------------
    // Country Code to Flag Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_country_code_to_flag_us() {
        assert_eq!(country_code_to_flag("US"), Some("🇺🇸".to_string()));
    }

    #[test]
    fn test_country_code_to_flag_jp() {
        assert_eq!(country_code_to_flag("JP"), Some("🇯🇵".to_string()));
    }

    #[test]
    fn test_country_code_to_flag_lowercase() {
        assert_eq!(country_code_to_flag("gb"), Some("🇬🇧".to_string()));
    }

    #[test]
    fn test_country_code_to_flag_invalid_length() {
        assert_eq!(country_code_to_flag("USA"), None);
        assert_eq!(country_code_to_flag("U"), None);
        assert_eq!(country_code_to_flag(""), None);
    }

    #[test]
    fn test_format_country_code_with_flag() {
        assert_eq!(format_country_code_with_flag("US"), "🇺🇸 US");
        assert_eq!(format_country_code_with_flag("JP"), "🇯🇵 JP");
        assert_eq!(format_country_code_with_flag("HK"), "🇭🇰 HK");
    }

    // ------------------------------------------------------------------------
    // Country Code Grouping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_group_outbounds_by_country() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 1", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 2", "1.1.1.2", 1080)),
            Outbound::Socks(SocksOutbound::new("🇯🇵 JP Server", "2.2.2.2", 1080)),
            Outbound::Direct(DirectOutbound::new("direct")), // No country code
        ];

        let groups = group_outbounds_by_country(&outbounds);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get("US").map(|v| v.len()), Some(2));
        assert_eq!(groups.get("JP").map(|v| v.len()), Some(1));
        assert!(
            groups
                .get("US")
                .unwrap()
                .contains(&"🇺🇸 US Server 1".to_string())
        );
        assert!(
            groups
                .get("US")
                .unwrap()
                .contains(&"🇺🇸 US Server 2".to_string())
        );
        assert!(
            groups
                .get("JP")
                .unwrap()
                .contains(&"🇯🇵 JP Server".to_string())
        );
    }

    // ------------------------------------------------------------------------
    // Selector Generation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_generate_country_code_selectors() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 1", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 2", "1.1.1.2", 1080)),
            Outbound::Socks(SocksOutbound::new("🇯🇵 JP Server", "2.2.2.2", 1080)),
        ];

        let selectors = generate_country_code_selectors(&outbounds);

        assert_eq!(selectors.len(), 2);

        // Check that we have JP and US selectors (sorted alphabetically by code)
        let tags: Vec<_> = selectors.iter().filter_map(get_outbound_tag).collect();
        assert_eq!(tags, vec!["🇯🇵 JP", "🇺🇸 US"]);

        // Check US selector has 2 outbounds
        if let Outbound::Selector(us_selector) = &selectors[1] {
            assert_eq!(us_selector.tag, Some("🇺🇸 US".to_string()));
            assert_eq!(us_selector.outbounds.len(), 2);
        } else {
            panic!("Expected Selector outbound");
        }

        // Check JP selector has 1 outbound
        if let Outbound::Selector(jp_selector) = &selectors[0] {
            assert_eq!(jp_selector.tag, Some("🇯🇵 JP".to_string()));
            assert_eq!(jp_selector.outbounds.len(), 1);
        } else {
            panic!("Expected Selector outbound");
        }
    }

    #[test]
    fn test_generate_country_code_selectors_filtered() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 1", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server 2", "1.1.1.2", 1080)),
            Outbound::Socks(SocksOutbound::new("🇯🇵 JP Server", "2.2.2.2", 1080)),
            Outbound::Socks(SocksOutbound::new("🇭🇰 HK Server", "3.3.3.3", 1080)),
            Outbound::Socks(SocksOutbound::new("🇬🇧 GB Server", "4.4.4.4", 1080)),
        ];

        // Filter to only US and JP
        let allowed = vec!["US".to_string(), "JP".to_string()];
        let selectors = generate_country_code_selectors_filtered(&outbounds, &allowed);

        assert_eq!(selectors.len(), 2);

        let tags: Vec<_> = selectors.iter().filter_map(get_outbound_tag).collect();
        assert_eq!(tags, vec!["🇯🇵 JP", "🇺🇸 US"]);
    }

    #[test]
    fn test_generate_country_code_selectors_filtered_case_insensitive() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("🇯🇵 JP Server", "2.2.2.2", 1080)),
        ];

        // Filter with lowercase
        let allowed = vec!["us".to_string(), "jp".to_string()];
        let selectors = generate_country_code_selectors_filtered(&outbounds, &allowed);

        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn test_generate_country_code_selectors_filtered_empty_allowed() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("🇺🇸 US Server", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("🇯🇵 JP Server", "2.2.2.2", 1080)),
        ];

        // Empty allowed list means all are included
        let selectors = generate_country_code_selectors_filtered(&outbounds, &[]);

        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn test_generate_subscription_selector() {
        let outbounds = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.1.1.1", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "2.2.2.2", 1080)),
        ];

        let selector = generate_subscription_selector("MySubscription", &outbounds);

        if let Outbound::Selector(s) = selector {
            assert_eq!(s.tag, Some("MySubscription".to_string()));
            assert_eq!(s.outbounds.len(), 2);
            assert!(s.outbounds.contains(&"proxy1".to_string()));
            assert!(s.outbounds.contains(&"proxy2".to_string()));
        } else {
            panic!("Expected Selector outbound");
        }
    }

    // ------------------------------------------------------------------------
    // Selector Update Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_update_selectors_with_new_tags() {
        let mut outbounds = vec![
            Outbound::Direct(DirectOutbound::new("direct")),
            Outbound::Selector(SelectorOutbound::new(
                "main",
                vec!["direct".to_string(), "block".to_string()],
            )),
            Outbound::UrlTest(UrlTestOutbound {
                tag: Some("auto".to_string()),
                outbounds: vec!["proxy1".to_string(), "proxy2".to_string()],
                ..Default::default()
            }),
        ];

        let new_tags = vec!["US".to_string(), "JP".to_string()];
        update_selectors_with_new_tags(&mut outbounds, &new_tags);

        // Check selector was updated
        if let Outbound::Selector(selector) = &outbounds[1] {
            assert_eq!(selector.outbounds.len(), 4);
            assert_eq!(selector.outbounds[0], "US");
            assert_eq!(selector.outbounds[1], "JP");
            assert_eq!(selector.outbounds[2], "direct");
            assert_eq!(selector.outbounds[3], "block");
        } else {
            panic!("Expected Selector outbound");
        }

        // Check urltest was updated
        if let Outbound::UrlTest(urltest) = &outbounds[2] {
            assert_eq!(urltest.outbounds.len(), 4);
            assert_eq!(urltest.outbounds[0], "US");
            assert_eq!(urltest.outbounds[1], "JP");
            assert_eq!(urltest.outbounds[2], "proxy1");
            assert_eq!(urltest.outbounds[3], "proxy2");
        } else {
            panic!("Expected UrlTest outbound");
        }

        // Direct outbound should be unchanged
        if let Outbound::Direct(direct) = &outbounds[0] {
            assert_eq!(direct.tag, Some("direct".to_string()));
        } else {
            panic!("Expected Direct outbound");
        }
    }

    #[test]
    fn test_update_selectors_with_empty_tags() {
        let mut outbounds = vec![Outbound::Selector(SelectorOutbound::new(
            "main",
            vec!["direct".to_string()],
        ))];

        update_selectors_with_new_tags(&mut outbounds, &[]);

        // Should remain unchanged
        if let Outbound::Selector(selector) = &outbounds[0] {
            assert_eq!(selector.outbounds.len(), 1);
            assert_eq!(selector.outbounds[0], "direct");
        } else {
            panic!("Expected Selector outbound");
        }
    }

    // ------------------------------------------------------------------------
    // Integration Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_full_transformation_workflow() {
        // Simulate a real workflow:
        // 1. Have some template outbounds with a selector
        // 2. Have subscription outbounds with country flags
        // 3. Generate selectors and update template

        let mut template_outbounds = vec![
            Outbound::Direct(DirectOutbound::new("direct")),
            Outbound::Selector(SelectorOutbound::new("proxy", vec!["direct".to_string()])),
        ];

        let subscription_outbounds = vec![
            Outbound::Shadowsocks(ShadowsocksOutbound {
                tag: Some("🇺🇸 US-1".to_string()),
                server: Some("1.1.1.1".to_string()),
                ..Default::default()
            }),
            Outbound::Shadowsocks(ShadowsocksOutbound {
                tag: Some("🇺🇸 US-2".to_string()),
                server: Some("1.1.1.2".to_string()),
                ..Default::default()
            }),
            Outbound::Shadowsocks(ShadowsocksOutbound {
                tag: Some("🇯🇵 JP-1".to_string()),
                server: Some("2.2.2.2".to_string()),
                ..Default::default()
            }),
        ];

        // Generate country code selectors
        let country_selectors = generate_country_code_selectors(&subscription_outbounds);
        assert_eq!(country_selectors.len(), 2);

        // Generate subscription selector
        let sub_selector = generate_subscription_selector("MyProvider", &subscription_outbounds);

        // Get tags for updating template selectors
        let new_selector_tags: Vec<String> = std::iter::once(&sub_selector)
            .chain(country_selectors.iter())
            .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
            .collect();

        assert_eq!(new_selector_tags, vec!["MyProvider", "🇯🇵 JP", "🇺🇸 US"]);

        // Update template selectors
        update_selectors_with_new_tags(&mut template_outbounds, &new_selector_tags);

        // Verify template selector was updated
        if let Outbound::Selector(selector) = &template_outbounds[1] {
            assert_eq!(selector.outbounds.len(), 4);
            assert_eq!(selector.outbounds[0], "MyProvider");
            assert_eq!(selector.outbounds[1], "🇯🇵 JP");
            assert_eq!(selector.outbounds[2], "🇺🇸 US");
            assert_eq!(selector.outbounds[3], "direct");
        } else {
            panic!("Expected Selector outbound");
        }
    }
}

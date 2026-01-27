//! Utility functions for serde serialization/deserialization.
//!
//! This module contains helper functions commonly used with serde's
//! `skip_serializing_if` and `default` attributes.

use serde::{Deserialize, Deserializer};

// ============================================================================
// Boolean Helpers
// ============================================================================

/// Returns `true` if the boolean value is `false`.
///
/// Used with `#[serde(skip_serializing_if = "is_false")]` to omit false values.
#[inline]
pub fn is_false(b: &bool) -> bool {
    !*b
}

/// Returns `true` if the boolean value is `true`.
///
/// Used with `#[serde(skip_serializing_if = "is_true")]` to omit true values.
#[inline]
pub fn is_true(b: &bool) -> bool {
    *b
}

// ============================================================================
// Numeric Zero Helpers
// ============================================================================

/// Returns `true` if the u16 value is zero.
///
/// Used with `#[serde(skip_serializing_if = "is_zero_u16")]` to omit zero values.
#[inline]
pub fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

/// Returns `true` if the u32 value is zero.
///
/// Used with `#[serde(skip_serializing_if = "is_zero_u32")]` to omit zero values.
#[inline]
pub fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// Returns `true` if the u64 value is zero.
///
/// Used with `#[serde(skip_serializing_if = "is_zero_u64")]` to omit zero values.
#[inline]
pub fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Returns `true` if the i32 value is zero.
///
/// Used with `#[serde(skip_serializing_if = "is_zero_i32")]` to omit zero values.
#[inline]
pub fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

// ============================================================================
// WireGuard MTU Helpers
// ============================================================================

/// Default WireGuard MTU value (1408).
pub const DEFAULT_WIREGUARD_MTU: u32 = 1408;

/// Returns the default WireGuard MTU value.
///
/// Used with `#[serde(default = "default_wireguard_mtu")]`.
#[inline]
pub fn default_wireguard_mtu() -> u32 {
    DEFAULT_WIREGUARD_MTU
}

/// Returns `true` if the MTU value is the default WireGuard MTU (1408).
///
/// Used with `#[serde(skip_serializing_if = "is_default_wireguard_mtu")]`.
#[inline]
pub fn is_default_wireguard_mtu(v: &u32) -> bool {
    *v == DEFAULT_WIREGUARD_MTU
}

// ============================================================================
// Collection Helpers
// ============================================================================

/// Returns `true` if the slice is empty.
///
/// Used with `#[serde(skip_serializing_if = "Vec::is_empty")]`.
/// Note: Usually you can use `Vec::is_empty` directly, but this is provided
/// for consistency.
#[inline]
pub fn is_empty_vec<T>(v: &[T]) -> bool {
    v.is_empty()
}

/// Returns `true` if the Option is None.
///
/// Used with `#[serde(skip_serializing_if = "Option::is_none")]`.
/// Note: Usually you can use `Option::is_none` directly, but this is provided
/// for consistency.
#[inline]
pub fn is_none<T>(v: &Option<T>) -> bool {
    v.is_none()
}

// ============================================================================
// String or Vec Deserializer
// ============================================================================

/// Helper enum for deserializing fields that can be either a single string or an array of strings.
///
/// Many sing-box config fields accept both formats:
/// - `"rule_set": "single-rule"` (single string)
/// - `"rule_set": ["rule1", "rule2"]` (array of strings)
#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

/// Deserializes a field that can be either a single string or an array of strings.
///
/// Use with `#[serde(default, deserialize_with = "string_or_vec")]`
///
/// # Example
/// ```ignore
/// #[derive(Deserialize)]
/// struct Rule {
///     #[serde(default, deserialize_with = "crate::config::util::string_or_vec")]
///     rule_set: Vec<String>,
/// }
/// ```
pub fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::Single(s) => Ok(vec![s]),
        StringOrVec::Multiple(v) => Ok(v),
    }
}

/// Deserializes an optional field that can be either a single string or an array of strings.
///
/// Use with `#[serde(default, deserialize_with = "option_string_or_vec")]`
pub fn option_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // This handles the case where the field exists but might be null
    let opt: Option<StringOrVec> = Option::deserialize(deserializer)?;
    match opt {
        Some(StringOrVec::Single(s)) => Ok(vec![s]),
        Some(StringOrVec::Multiple(v)) => Ok(v),
        None => Ok(Vec::new()),
    }
}

// ============================================================================
// U16 or Vec Deserializer (for port fields)
// ============================================================================

/// Helper enum for deserializing fields that can be either a single u16 or an array of u16.
///
/// Many sing-box config fields accept both formats:
/// - `"port": 53` (single integer)
/// - `"port": [53, 80, 443]` (array of integers)
#[derive(Deserialize)]
#[serde(untagged)]
enum U16OrVec {
    Single(u16),
    Multiple(Vec<u16>),
}

/// Deserializes a field that can be either a single u16 or an array of u16.
///
/// Use with `#[serde(default, deserialize_with = "u16_or_vec")]`
///
/// # Example
/// ```ignore
/// #[derive(Deserialize)]
/// struct Rule {
///     #[serde(default, deserialize_with = "crate::config::util::u16_or_vec")]
///     port: Vec<u16>,
/// }
/// ```
pub fn u16_or_vec<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    match U16OrVec::deserialize(deserializer)? {
        U16OrVec::Single(n) => Ok(vec![n]),
        U16OrVec::Multiple(v) => Ok(v),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_false() {
        assert!(is_false(&false));
        assert!(!is_false(&true));
    }

    #[test]
    fn test_is_true() {
        assert!(is_true(&true));
        assert!(!is_true(&false));
    }

    #[test]
    fn test_is_zero_u16() {
        assert!(is_zero_u16(&0));
        assert!(!is_zero_u16(&1));
        assert!(!is_zero_u16(&65535));
    }

    #[test]
    fn test_is_zero_u32() {
        assert!(is_zero_u32(&0));
        assert!(!is_zero_u32(&1));
        assert!(!is_zero_u32(&100));
    }

    #[test]
    fn test_is_zero_u64() {
        assert!(is_zero_u64(&0));
        assert!(!is_zero_u64(&1));
    }

    #[test]
    fn test_is_zero_i32() {
        assert!(is_zero_i32(&0));
        assert!(!is_zero_i32(&1));
        assert!(!is_zero_i32(&-1));
    }

    #[test]
    fn test_default_wireguard_mtu() {
        assert_eq!(default_wireguard_mtu(), 1408);
    }

    #[test]
    fn test_is_default_wireguard_mtu() {
        assert!(is_default_wireguard_mtu(&1408));
        assert!(!is_default_wireguard_mtu(&1500));
        assert!(!is_default_wireguard_mtu(&0));
    }

    #[test]
    fn test_is_empty_vec() {
        let empty: Vec<i32> = vec![];
        let non_empty = vec![1, 2, 3];
        assert!(is_empty_vec(&empty));
        assert!(!is_empty_vec(&non_empty));
    }

    #[test]
    fn test_is_none() {
        let none: Option<i32> = None;
        let some = Some(42);
        assert!(is_none(&none));
        assert!(!is_none(&some));
    }

    #[test]
    fn test_string_or_vec_single() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::string_or_vec")]
            values: Vec<String>,
        }

        let json = r#"{"values": "single"}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.values, vec!["single"]);
    }

    #[test]
    fn test_string_or_vec_multiple() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::string_or_vec")]
            values: Vec<String>,
        }

        let json = r#"{"values": ["one", "two", "three"]}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.values, vec!["one", "two", "three"]);
    }

    #[test]
    fn test_string_or_vec_missing() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::string_or_vec")]
            values: Vec<String>,
        }

        let json = r#"{}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert!(result.values.is_empty());
    }

    #[test]
    fn test_u16_or_vec_single() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::u16_or_vec")]
            ports: Vec<u16>,
        }

        let json = r#"{"ports": 53}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.ports, vec![53]);
    }

    #[test]
    fn test_u16_or_vec_multiple() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::u16_or_vec")]
            ports: Vec<u16>,
        }

        let json = r#"{"ports": [53, 80, 443]}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.ports, vec![53, 80, 443]);
    }

    #[test]
    fn test_u16_or_vec_missing() {
        #[derive(Deserialize)]
        struct TestStruct {
            #[serde(default, deserialize_with = "super::u16_or_vec")]
            ports: Vec<u16>,
        }

        let json = r#"{}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert!(result.ports.is_empty());
    }
}

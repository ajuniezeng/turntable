//! Utility functions for serde serialization/deserialization.
//!
//! This module contains helper functions commonly used with serde's
//! `skip_serializing_if` and `default` attributes.

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
}

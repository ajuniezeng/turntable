//! Base64 decoding utilities
//!
//! This module provides functionality for decoding Base64-encoded subscription
//! content, supporting multiple Base64 variants including standard, URL-safe,
//! and content with or without padding.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use tracing::trace;

// ============================================================================
// Base64 Decoding
// ============================================================================

/// Decodes Base64 content, trying multiple variants
///
/// Attempts to decode the content using:
/// 1. Standard Base64
/// 2. URL-safe Base64
/// 3. URL-safe Base64 without padding
/// 4. Standard/URL-safe with padding added
///
/// Whitespace in the input is automatically removed before decoding.
pub fn decode_base64(content: &str) -> Result<Vec<u8>> {
    // Remove all whitespace (handles line breaks within Base64)
    let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    trace!(
        "Attempting Base64 decode, cleaned length: {} bytes",
        cleaned.len()
    );

    // Try standard Base64 first
    if let Ok(decoded) = STANDARD.decode(&cleaned) {
        trace!("Decoded using standard Base64");
        return Ok(decoded);
    }

    // Try URL-safe Base64
    if let Ok(decoded) = URL_SAFE.decode(&cleaned) {
        trace!("Decoded using URL-safe Base64");
        return Ok(decoded);
    }

    // Try URL-safe Base64 without padding
    if let Ok(decoded) = URL_SAFE_NO_PAD.decode(&cleaned) {
        trace!("Decoded using URL-safe Base64 without padding");
        return Ok(decoded);
    }

    // Try with padding added if needed
    let padded = add_base64_padding(&cleaned);
    if let Ok(decoded) = STANDARD.decode(&padded) {
        trace!("Decoded using standard Base64 with added padding");
        return Ok(decoded);
    }
    if let Ok(decoded) = URL_SAFE.decode(&padded) {
        trace!("Decoded using URL-safe Base64 with added padding");
        return Ok(decoded);
    }

    bail!("Failed to decode Base64 content")
}

/// Adds proper padding to Base64 string if missing
///
/// Base64 strings should have a length that is a multiple of 4.
/// This function adds '=' padding characters as needed.
pub fn add_base64_padding(s: &str) -> String {
    let mut result = s.to_string();
    while !result.len().is_multiple_of(4) {
        result.push('=');
    }
    result
}

/// Decodes subscription content, automatically handling Base64 if needed
///
/// This function detects whether the content is Base64-encoded and decodes it
/// if necessary. Non-Base64 content is returned as-is.
pub fn decode_subscription_content(content: &str) -> Result<String> {
    use super::detection::SubscriptionType;
    use super::detection::detect_subscription_type;

    let subscription_type = detect_subscription_type(content);

    match subscription_type {
        SubscriptionType::Base64UriList => {
            let decoded = decode_base64(content.trim())?;
            String::from_utf8(decoded).context("Decoded Base64 content is not valid UTF-8")
        }
        _ => Ok(content.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_standard() {
        // "hello world" in standard Base64
        let encoded = "aGVsbG8gd29ybGQ=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn test_decode_base64_url_safe() {
        // URL-safe Base64 with - and _ instead of + and /
        let encoded = "aGVsbG8td29ybGQ_"; // "hello-world?" with URL-safe encoding
        let result = decode_base64(encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_base64_with_linebreaks() {
        let encoded = "aGVs\nbG8g\nd29y\nbGQ=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn test_decode_base64_without_padding() {
        // "hello world" without padding (should have 1 padding char)
        let encoded = "aGVsbG8gd29ybGQ";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn test_decode_base64_with_whitespace() {
        let encoded = "  aGVsbG8gd29ybGQ=  ";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn test_decode_base64_with_tabs() {
        let encoded = "aGVs\tbG8g\td29ybGQ=";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
    }

    #[test]
    fn test_decode_base64_empty() {
        let encoded = "";
        let result = decode_base64(encoded);
        // Empty string decodes to empty bytes
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_base64_invalid() {
        let encoded = "not valid base64!!!";
        let result = decode_base64(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_base64_padding_none_needed() {
        assert_eq!(add_base64_padding("abcd"), "abcd");
        assert_eq!(add_base64_padding("abcdabcd"), "abcdabcd");
    }

    #[test]
    fn test_add_base64_padding_one_needed() {
        assert_eq!(add_base64_padding("abc"), "abc=");
    }

    #[test]
    fn test_add_base64_padding_two_needed() {
        assert_eq!(add_base64_padding("ab"), "ab==");
    }

    #[test]
    fn test_add_base64_padding_three_needed() {
        assert_eq!(add_base64_padding("a"), "a===");
    }

    #[test]
    fn test_add_base64_padding_empty() {
        assert_eq!(add_base64_padding(""), "");
    }

    #[test]
    fn test_decode_base64_complex_content() {
        // A more realistic test with a URI-like content
        use base64::engine::general_purpose::STANDARD;
        let original = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#test";
        let encoded = STANDARD.encode(original);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), original);
    }

    #[test]
    fn test_decode_base64_multiline_uri_list() {
        use base64::engine::general_purpose::STANDARD;
        let original = "ss://abc@host1:1234#node1\nvmess://xyz@host2:5678#node2";
        let encoded = STANDARD.encode(original);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), original);
    }
}

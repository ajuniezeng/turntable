//! Generator utility functions
//!
//! This module provides common utility functions used by the generator,
//! including path expansion, HTTP fetching, and user prompts.

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::get_version;

// ============================================================================
// Path Utilities
// ============================================================================

/// Expand ~ to home directory in path
pub fn expand_tilde(path: &str) -> String {
    if (path.starts_with("~/") || path == "~")
        && let Some(home) = dirs_home()
    {
        return path.replacen("~", &home, 1);
    }
    path.to_string()
}

/// Get home directory path
pub fn dirs_home() -> Option<String> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").ok()
    }
}

// ============================================================================
// HTTP Utilities
// ============================================================================

/// Fetch text content from a URL
pub async fn fetch_text(url: &str) -> Result<String> {
    debug!("Fetching URL: {}", url);

    let client = reqwest::Client::builder()
        .user_agent(format!("turntable/{}", get_version()))
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch URL: {}", url))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("HTTP request failed with status {}: {}", status, url);
    }

    let text = response
        .text()
        .await
        .with_context(|| format!("Failed to read response body from: {}", url))?;

    Ok(text)
}

// ============================================================================
// User Prompts
// ============================================================================

/// Prompt user to select a default outbound for the detour selector.
///
/// Returns `Some(tag)` if user selects an outbound, `None` if user skips.
pub fn prompt_detour_default(outbound_tags: &[String]) -> Option<String> {
    use dialoguer::{Select, theme::ColorfulTheme};

    if outbound_tags.is_empty() {
        return None;
    }

    // Add "Skip (no default)" option at the beginning
    let mut items: Vec<&str> = vec!["(Skip - no default)"];
    items.extend(outbound_tags.iter().map(|s| s.as_str()));

    println!();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select default outbound for detour selector")
        .items(&items)
        .default(0)
        .interact();

    match selection {
        Ok(0) => {
            info!("User skipped selecting default outbound");
            None
        }
        Ok(idx) => {
            let selected = outbound_tags[idx - 1].clone();
            info!("User selected default outbound: {}", selected);
            Some(selected)
        }
        Err(e) => {
            warn!("Failed to get user selection: {}, skipping default", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_expand_tilde_with_home() {
        if let Ok(home) = env::var("HOME") {
            let expanded = expand_tilde("~/test/path");
            assert!(expanded.starts_with(&home));
            assert!(expanded.ends_with("/test/path"));
            assert!(!expanded.contains('~'));
        }
    }

    #[test]
    fn test_expand_tilde_just_tilde() {
        if let Ok(home) = env::var("HOME") {
            let expanded = expand_tilde("~");
            assert_eq!(expanded, home);
        }
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let path = "/absolute/path/to/file";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_expand_tilde_relative_path() {
        let path = "./relative/path";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_expand_tilde_tilde_in_middle() {
        // Tilde in the middle should not be expanded
        let path = "/some/~/path";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_expand_tilde_absolute_path() {
        let path = "/usr/local/bin";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_dirs_home_returns_some() {
        // HOME should be set in most test environments
        if env::var("HOME").is_ok() || env::var("USERPROFILE").is_ok() {
            assert!(dirs_home().is_some());
        }
    }

    #[test]
    fn test_prompt_detour_default_empty_tags() {
        let tags: Vec<String> = vec![];
        let result = prompt_detour_default(&tags);
        assert!(result.is_none());
    }
}

//! Subscription caching functionality
//!
//! This module provides caching for subscription data to avoid
//! unnecessary network requests when subscriptions haven't changed.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tracing::debug;

use crate::config::outbound::Outbound;
use crate::generator::subscription::SingBoxSubscription;

// ============================================================================
// Cache Manager
// ============================================================================

/// Manages subscription caching
pub struct CacheManager {
    /// Directory where cache files are stored
    cache_dir: PathBuf,
    /// Cache time-to-live in minutes
    ttl_minutes: u64,
    /// Whether caching is enabled
    enabled: bool,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(cache_dir: PathBuf, ttl_minutes: u64, enabled: bool) -> Self {
        Self {
            cache_dir,
            ttl_minutes,
            enabled,
        }
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the cache file path for a subscription
    pub fn get_cache_path(&self, subscription_name: &str) -> PathBuf {
        // Sanitize subscription name for use as filename
        let safe_name: String = subscription_name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.cache_dir.join(format!("{}.cache.json", safe_name))
    }

    /// Check if a cached subscription is still valid (within TTL)
    pub fn is_cache_valid(&self, cache_path: &Path) -> bool {
        if !self.enabled {
            return false;
        }

        if let Ok(metadata) = std::fs::metadata(cache_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = SystemTime::now().duration_since(modified)
        {
            let ttl = Duration::from_secs(self.ttl_minutes * 60);
            return elapsed < ttl;
        }
        false
    }

    /// Load outbounds from cache file
    pub async fn load_from_cache(&self, cache_path: &Path) -> Result<Vec<Outbound>> {
        let content = tokio::fs::read_to_string(cache_path)
            .await
            .with_context(|| format!("Failed to read cache file: {}", cache_path.display()))?;

        let subscription: SingBoxSubscription = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse cache file: {}", cache_path.display()))?;

        Ok(subscription.outbounds)
    }

    /// Load outbounds from cache file if it exists (regardless of TTL)
    /// Used for diffing purposes
    pub async fn load_from_cache_if_exists(&self, cache_path: &Path) -> Option<Vec<Outbound>> {
        if !cache_path.exists() {
            return None;
        }

        match tokio::fs::read_to_string(cache_path).await {
            Ok(content) => match serde_json::from_str::<SingBoxSubscription>(&content) {
                Ok(subscription) => Some(subscription.outbounds),
                Err(e) => {
                    debug!("Failed to parse cache file for diff: {}", e);
                    None
                }
            },
            Err(e) => {
                debug!("Failed to read cache file for diff: {}", e);
                None
            }
        }
    }

    /// Save outbounds to cache file
    pub async fn save_to_cache(&self, cache_path: &Path, outbounds: &[Outbound]) -> Result<()> {
        // Ensure cache directory exists
        if let Some(parent) = cache_path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create cache directory: {}", parent.display())
            })?;
        }

        let subscription = SingBoxSubscription::with_outbounds(outbounds.to_vec());

        let content = serde_json::to_string_pretty(&subscription)
            .context("Failed to serialize outbounds for cache")?;

        tokio::fs::write(cache_path, content)
            .await
            .with_context(|| format!("Failed to write cache file: {}", cache_path.display()))?;

        debug!(
            "Saved {} outbounds to cache: {}",
            outbounds.len(),
            cache_path.display()
        );
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get the cache directory path from the output file path
/// (uses the same directory as the output file)
pub fn get_cache_dir_from_output(output_path: &str) -> PathBuf {
    let expanded_output = super::helpers::expand_tilde(output_path);
    let output_path = Path::new(&expanded_output);
    output_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_cache_manager_new() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, true);
        assert_eq!(manager.cache_dir(), Path::new("/tmp/cache"));
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_cache_manager_disabled() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, false);
        assert!(!manager.is_enabled());
    }

    #[test]
    fn test_get_cache_path_simple() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, true);
        let path = manager.get_cache_path("MyProvider");
        assert_eq!(path, PathBuf::from("/tmp/cache/MyProvider.cache.json"));
    }

    #[test]
    fn test_get_cache_path_sanitizes_special_chars() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, true);
        let path = manager.get_cache_path("My Provider/Special:Name");
        assert_eq!(
            path,
            PathBuf::from("/tmp/cache/My_Provider_Special_Name.cache.json")
        );
    }

    #[test]
    fn test_get_cache_path_preserves_valid_chars() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, true);
        let path = manager.get_cache_path("provider-name_123");
        assert_eq!(
            path,
            PathBuf::from("/tmp/cache/provider-name_123.cache.json")
        );
    }

    #[test]
    fn test_is_cache_valid_disabled() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, false);
        assert!(!manager.is_cache_valid(Path::new("/tmp/cache/test.cache.json")));
    }

    #[test]
    fn test_is_cache_valid_nonexistent() {
        let manager = CacheManager::new(PathBuf::from("/tmp/cache"), 60, true);
        assert!(!manager.is_cache_valid(Path::new("/nonexistent/path/test.cache.json")));
    }

    #[test]
    fn test_get_cache_dir_from_output_with_dir() {
        let dir = get_cache_dir_from_output("./out/config.json");
        assert_eq!(dir, PathBuf::from("./out"));
    }

    #[test]
    fn test_get_cache_dir_from_output_no_dir() {
        let dir = get_cache_dir_from_output("config.json");
        assert_eq!(dir, PathBuf::from(""));
    }

    #[test]
    fn test_get_cache_dir_from_output_with_tilde() {
        // This test depends on HOME being set
        if env::var("HOME").is_ok() {
            let dir = get_cache_dir_from_output("~/out/config.json");
            assert!(dir.to_string_lossy().contains("out"));
            assert!(!dir.to_string_lossy().starts_with("~"));
        }
    }
}

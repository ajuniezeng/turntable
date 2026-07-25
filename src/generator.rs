//! Configuration generator module
//!
//! This module orchestrates the generation of sing-box configuration files
//! from templates and subscription sources.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::config::SingBoxConfig;
use crate::config::dns::Strategy;
use crate::config::document::SingBoxDocument;
use crate::config::outbound::Outbound;
use crate::config::version::SingBoxVersion;
use crate::parser::{SubscriptionType, detect_subscription_type, parse_subscription};
use crate::transform::{
    DETOUR_SELECTOR_TAG, collect_non_detour_tags, filter_detour_outbounds, filter_ipv6_outbounds,
    generate_country_code_selectors_filtered, generate_detour_selector,
    generate_subscription_selector, get_outbound_tag,
};
use crate::webdav::upload_to_webdav;

// Sub-modules
pub mod cache;
pub mod diff;
pub mod generator_config;
pub mod helpers;
pub mod native_check;
pub mod subscription;

// Re-exports
pub use cache::{CacheManager, get_cache_dir_from_output};
pub use diff::{DiffResult, diff_outbounds, log_diff};
pub use generator_config::GeneratorConfig;
pub use helpers::{expand_tilde, fetch_text, prompt_detour_default};
pub use subscription::{SingBoxSubscription, Subscription};

// ============================================================================
// Generator
// ============================================================================

/// Generator that orchestrates the config generation process
pub struct Generator {
    config: GeneratorConfig,
    cache: CacheManager,
}

impl Generator {
    /// Create a new generator with the given config
    pub fn new(config: GeneratorConfig) -> Self {
        let cache_dir = get_cache_dir_from_output(&config.output);
        let cache = CacheManager::new(cache_dir, config.cache_ttl, config.cache_subscription);
        Self { config, cache }
    }

    /// Load generator from path or URL
    pub async fn load(path_or_url: &str) -> Result<Self> {
        let config = GeneratorConfig::load(path_or_url).await?;
        Ok(Self::new(config))
    }

    /// Run the generation process
    pub async fn generate(&self) -> Result<SingBoxDocument> {
        info!("Starting config generation");
        if crate::config::schema::is_alias(&self.config.target_version) {
            warn!(
                target = self.config.target_version,
                resolved = self.config.resolved_target_version(),
                "Using a compatibility target alias; prefer the exact release identifier"
            );
        }

        // 1. Load template
        let mut config = self.load_template().await?;
        debug!(
            "Loaded template with {} outbounds",
            config
                .outbound_count()
                .context("Invalid template outbounds")?
        );

        // 2. Fetch and parse all subscriptions (keeping track of subscription names)
        let subscriptions_with_outbounds = self.fetch_subscriptions_with_names().await?;
        let total_fetched: usize = subscriptions_with_outbounds
            .iter()
            .map(|(_, outbounds)| outbounds.len())
            .sum();
        debug!("Fetched {} outbounds from subscriptions", total_fetched);

        // 3. Apply ipv4_only filter if enabled
        let subscriptions_with_outbounds = if self.config.ipv4_only {
            info!("Filtering out IPv6 outbounds (ipv4_only=true)");

            // Set DNS strategy to ipv4_only
            config
                .set_dns_strategy(Strategy::Ipv4Only)
                .context("Failed to update template DNS strategy")?;
            debug!("Set DNS strategy to ipv4_only");

            subscriptions_with_outbounds
                .into_iter()
                .map(|(name, outbounds)| (name, filter_ipv6_outbounds(outbounds)))
                .collect()
        } else {
            subscriptions_with_outbounds
        };

        // 4. Apply no_detour filter or detour_selector if enabled
        let (subscriptions_with_outbounds, detour_selector) = if self.config.no_detour {
            info!("Filtering out outbounds with detour (no_detour=true)");
            let filtered: Vec<(String, Vec<Outbound>)> = subscriptions_with_outbounds
                .into_iter()
                .map(|(name, outbounds)| (name, filter_detour_outbounds(outbounds)))
                .collect();
            (filtered, None)
        } else if self.config.detour_selector {
            info!("Generating detour selector (detour_selector=true)");
            // Collect all outbounds, generate detour selector, and update detour references
            let mut all_outbounds: Vec<Outbound> = subscriptions_with_outbounds
                .iter()
                .flat_map(|(_, outbounds)| outbounds.clone())
                .collect();

            // Prompt user to select default outbound for detour selector
            let non_detour_tags = collect_non_detour_tags(&all_outbounds);
            let default_outbound = if non_detour_tags.is_empty() {
                warn!("No non-detour outbounds found for detour selector");
                None
            } else {
                prompt_detour_default(&non_detour_tags)
            };

            let selector = generate_detour_selector(&mut all_outbounds, default_outbound);

            // Redistribute updated outbounds back to their subscriptions
            let mut outbound_idx = 0;
            let updated_subscriptions: Vec<(String, Vec<Outbound>)> = subscriptions_with_outbounds
                .into_iter()
                .map(|(name, outbounds)| {
                    let count = outbounds.len();
                    let updated: Vec<Outbound> =
                        all_outbounds[outbound_idx..outbound_idx + count].to_vec();
                    outbound_idx += count;
                    (name, updated)
                })
                .collect();

            (updated_subscriptions, Some(selector))
        } else {
            (subscriptions_with_outbounds, None)
        };

        // 5. Collect all subscription outbounds for country code processing
        let all_subscription_outbounds: Vec<Outbound> = subscriptions_with_outbounds
            .iter()
            .flat_map(|(_, outbounds)| outbounds.clone())
            .collect();

        // 6. Generate subscription selectors (one per subscription)
        let subscription_selectors: Vec<Outbound> = subscriptions_with_outbounds
            .iter()
            .map(|(name, outbounds)| generate_subscription_selector(name, outbounds))
            .collect();
        info!(
            "Generated {} subscription selectors",
            subscription_selectors.len()
        );

        // 7. Generate country code selectors if enabled
        let country_selectors = if self.config.country_code_outbound_selectors {
            let selectors = generate_country_code_selectors_filtered(
                &all_subscription_outbounds,
                &self.config.country_codes,
            );
            if self.config.country_codes.is_empty() {
                info!("Generated {} country code selectors (all)", selectors.len());
            } else {
                info!(
                    "Generated {} country code selectors (filtered to {:?})",
                    selectors.len(),
                    self.config.country_codes
                );
            }
            selectors
        } else {
            Vec::new()
        };

        // 8. Collect all new selector tags for updating template selectors
        // Order: subscription selectors first, then country code selectors (alphabetically sorted)
        let new_selector_tags: Vec<String> = subscription_selectors
            .iter()
            .chain(country_selectors.iter())
            .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
            .collect();

        // 9. Update existing selectors in template with new selector tags
        if !new_selector_tags.is_empty() {
            debug!(
                "Updating template selectors with {} new tags",
                new_selector_tags.len()
            );
            config
                .update_selectors(&new_selector_tags)
                .context("Failed to update template selectors")?;
        }

        // 10. Add all new outbounds to config:
        //    - Detour selector (if enabled)
        //    - Subscription selectors
        //    - Country code selectors
        //    - All subscription outbounds
        if let Some(selector) = detour_selector {
            info!("Adding detour selector '{}'", DETOUR_SELECTOR_TAG);
            config
                .extend_outbounds(std::iter::once(selector))
                .context("Failed to append detour selector")?;
        }
        config
            .extend_outbounds(subscription_selectors)
            .context("Failed to append subscription selectors")?;
        config
            .extend_outbounds(country_selectors)
            .context("Failed to append country selectors")?;
        config
            .extend_outbounds(all_subscription_outbounds)
            .context("Failed to append subscription outbounds")?;

        if let Some(schema_bundle) = self.config.get_schema_bundle() {
            config.ensure_schema_uri_for(schema_bundle);
            config
                .validate_schema_with(schema_bundle)
                .context("Generated configuration does not match the official sing-box schema")?;
        }

        info!(
            "Final config has {} outbounds",
            config
                .outbound_count()
                .context("Invalid generated outbounds")?
        );

        Ok(config)
    }

    /// Generate and write to output file
    pub async fn generate_to_file(&self, output_override: Option<&str>) -> Result<()> {
        let config = self.generate().await?;

        // Get target version for validation
        info!(
            "Validating config for sing-box version {}",
            self.config.resolved_target_version()
        );

        if let Some(schema_bundle) = self.config.get_schema_bundle() {
            info!(
                "Configuration matches the official sing-box {} schema",
                schema_bundle.release()
            );

            let warnings = config
                .validate_semantics_with(schema_bundle)
                .context("Generated configuration has invalid cross-references")?;
            for warning in warnings {
                warn!(warning = %warning, "configuration semantic warning");
            }
        } else {
            // Older sing-box releases predate the official schema. Preserve
            // the existing typed compatibility checks for those targets.
            let target_version = self.config.get_target_version();
            let typed: SingBoxConfig = serde_json::from_value(config.to_value())
                .context("Failed to build legacy validation view")?;
            log_typed_validation(&typed, &target_version);
        }

        let output_path = output_override.unwrap_or(&self.config.output);
        let expanded_path = expand_tilde(output_path);
        let path = Path::new(&expanded_path);
        let output_directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        // Create parent directories if they don't exist
        tokio::fs::create_dir_all(output_directory)
            .await
            .with_context(|| format!("Failed to create output directory {:?}", output_directory))?;

        // Serialize to pretty JSON
        let json = config
            .to_json_pretty()
            .context("Failed to serialize config to JSON")?;

        if let Some(binary) = &self.config.sing_box_binary {
            native_check::validate(
                binary,
                &json,
                output_directory,
                self.config
                    .get_schema_bundle()
                    .map(crate::config::schema::SchemaBundle::release),
            )
            .await
            .context("Configured sing-box binary rejected the generated configuration")?;
        }

        // Write to file
        tokio::fs::write(path, &json)
            .await
            .with_context(|| format!("Failed to write config to {:?}", path))?;

        info!("Config written to {:?}", path);

        // Upload to WebDAV if configured
        let webdav_config = self.config.get_webdav_config();
        if webdav_config.is_configured() {
            upload_to_webdav(&webdav_config, &json).await?;
        }

        Ok(())
    }

    /// Load the template configuration
    async fn load_template(&self) -> Result<SingBoxDocument> {
        let template_path = &self.config.template;
        info!("Loading template from {}", template_path);

        let content =
            if template_path.starts_with("http://") || template_path.starts_with("https://") {
                fetch_text(template_path).await?
            } else {
                let expanded = expand_tilde(template_path);
                tokio::fs::read_to_string(&expanded)
                    .await
                    .with_context(|| format!("Failed to read template from {}", expanded))?
            };

        let config = if let Some(schema_bundle) = self.config.get_schema_bundle() {
            SingBoxDocument::from_json_with_schema(&content, schema_bundle)
                .context("Template does not match the official sing-box schema")?
        } else {
            SingBoxDocument::from_json_unchecked(&content)
                .context("Failed to parse template as sing-box config")?
        };

        Ok(config)
    }

    /// Fetch all subscriptions and collect their outbounds with subscription names.
    ///
    /// Returns a vector of (subscription_name, outbounds) tuples.
    async fn fetch_subscriptions_with_names(&self) -> Result<Vec<(String, Vec<Outbound>)>> {
        let mut results = Vec::new();
        let total_subscriptions = self.config.subscriptions.len();

        debug!("Starting to fetch {} subscription(s)", total_subscriptions);

        for (index, sub) in self.config.subscriptions.iter().enumerate() {
            // Check cache first if caching is enabled
            let cache_path = self.cache.get_cache_path(&sub.name);
            let use_cache = self.cache.is_cache_valid(&cache_path);

            if use_cache {
                info!(
                    "Loading subscription [{}/{}]: '{}' from cache",
                    index + 1,
                    total_subscriptions,
                    sub.name
                );
                match self.cache.load_from_cache(&cache_path).await {
                    Ok(outbounds) => {
                        info!(
                            "Loaded {} outbounds from cache for '{}'",
                            outbounds.len(),
                            sub.name
                        );
                        results.push((
                            sub.name.clone(),
                            self.apply_subscription_filter(sub, outbounds),
                        ));
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load cache for '{}': {}, fetching fresh",
                            sub.name, e
                        );
                    }
                }
            }

            info!(
                "Fetching subscription [{}/{}]: '{}' from {}",
                index + 1,
                total_subscriptions,
                sub.name,
                sub.url
            );

            match self.fetch_singbox_subscription(&sub.url).await {
                Ok(outbounds) => {
                    // Diff with cached version if enabled and cache exists
                    if self.config.diff_subscription {
                        if let Some(cached_outbounds) =
                            self.cache.load_from_cache_if_exists(&cache_path).await
                        {
                            log_diff(&sub.name, &cached_outbounds, &outbounds);
                        } else {
                            info!(
                                "Subscription '{}': First fetch, {} outbounds",
                                sub.name,
                                outbounds.len()
                            );
                        }
                    }

                    // Save to cache if caching is enabled (before filtering)
                    if self.cache.is_enabled()
                        && let Err(e) = self.cache.save_to_cache(&cache_path, &outbounds).await
                    {
                        warn!("Failed to save cache for '{}': {}", sub.name, e);
                    }

                    // Apply filter if specified
                    let outbounds = self.apply_subscription_filter(sub, outbounds);

                    info!(
                        "Subscription '{}' returned {} outbounds",
                        sub.name,
                        outbounds.len()
                    );
                    for outbound in &outbounds {
                        let tag = get_outbound_tag(outbound)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "<no tag>".to_string());
                        debug!("  - {}: {}", sub.name, tag);
                    }

                    results.push((sub.name.clone(), outbounds));
                }
                Err(e) => {
                    // Log error but continue with other subscriptions
                    warn!("Failed to fetch subscription '{}': {}", sub.name, e);
                    debug!("Error details for '{}': {:?}", sub.name, e);
                }
            }
        }

        let total_outbounds: usize = results.iter().map(|(_, o)| o.len()).sum();
        debug!(
            "Subscription fetching complete: {} subscription(s) successful, {} total outbounds",
            results.len(),
            total_outbounds
        );

        Ok(results)
    }

    /// Apply subscription filter to outbounds
    fn apply_subscription_filter(
        &self,
        sub: &Subscription,
        outbounds: Vec<Outbound>,
    ) -> Vec<Outbound> {
        if sub.filter.is_empty() {
            outbounds
        } else {
            let original_count = outbounds.len();
            let filtered: Vec<_> = outbounds
                .into_iter()
                .enumerate()
                .filter(|(i, _)| !sub.filter.contains(i))
                .map(|(_, o)| o)
                .collect();
            debug!(
                "Filtered subscription '{}': removed {} outbounds (indices {:?}), {} remaining",
                sub.name,
                original_count - filtered.len(),
                sub.filter,
                filtered.len()
            );
            filtered
        }
    }

    /// Fetch and parse a subscription, automatically detecting the format
    async fn fetch_singbox_subscription(&self, url: &str) -> Result<Vec<Outbound>> {
        debug!("Fetching subscription content from: {}", url);
        let content = fetch_text(url).await?;
        debug!(
            "Received {} bytes of content from subscription",
            content.len()
        );

        let subscription_type = detect_subscription_type(&content);
        debug!(
            "Detected subscription type: {} for URL: {}",
            subscription_type, url
        );

        match subscription_type {
            SubscriptionType::Unknown => {
                let preview: String = content.chars().take(200).collect();
                debug!("Content preview for unknown format: {:?}", preview);
                anyhow::bail!("Unable to detect subscription format for URL: {}", url)
            }
            SubscriptionType::ClashYaml => {
                debug!("Clash YAML detected but not supported");
                anyhow::bail!("Clash YAML format is not yet supported for URL: {}", url)
            }
            _ => {
                debug!("Starting subscription parsing...");
                let outbounds = parse_subscription(&content)
                    .with_context(|| format!("Failed to parse subscription from: {}", url))?;
                debug!(
                    "Successfully parsed {} outbounds from {}",
                    outbounds.len(),
                    url
                );
                Ok(outbounds)
            }
        }
    }

    /// Diff two sets of outbounds and log the differences (legacy method for compatibility)
    #[allow(dead_code)]
    fn diff_outbounds(&self, subscription_name: &str, old: &[Outbound], new: &[Outbound]) {
        let old_tags: HashSet<String> = old
            .iter()
            .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
            .collect();

        let new_tags: HashSet<String> = new
            .iter()
            .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
            .collect();

        let added: Vec<&String> = new_tags.difference(&old_tags).collect();
        let removed: Vec<&String> = old_tags.difference(&new_tags).collect();

        if added.is_empty() && removed.is_empty() {
            info!(
                "Subscription '{}': No changes ({} outbounds)",
                subscription_name,
                new_tags.len()
            );
            return;
        }

        info!(
            "Subscription '{}' changes: +{} added, -{} removed",
            subscription_name,
            added.len(),
            removed.len()
        );

        if !added.is_empty() {
            info!("  Added ({}):", added.len());
            for tag in &added {
                info!("    + {}", tag);
            }
        }

        if !removed.is_empty() {
            info!("  Removed ({}):", removed.len());
            for tag in &removed {
                info!("    - {}", tag);
            }
        }
    }
}

fn log_typed_validation(config: &SingBoxConfig, target_version: &SingBoxVersion) {
    let validation_result = config.validate_for_version(target_version);
    if validation_result.has_warnings() {
        warn!(
            "Configuration has {} warning(s)",
            validation_result.warning_count()
        );
        validation_result.log_warnings();
    }
    if validation_result.has_errors() {
        warn!(
            "Configuration has {} validation error(s)",
            validation_result.error_count()
        );
        validation_result.log_errors();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

    const EXAMPLE_GENERATOR_TOML: &str = r#"
    template = "./templates/1.13.json"
    output = "./out/config.json"
    ipv4_only = false
    target_version = "1.13"
    country_code_outbound_selectors = true
    no_detour = false
    detour_selector = false
    cache_subscription = false
    cache_ttl = 60
    diff_subscription = false

    [[subscriptions]]
    name = "MyProvider"
    url = "https://example.com/subscription-url"
    "#;

    const MINIMAL_GENERATOR_TOML: &str = r#"
template = "./template.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;

    fn temporary_template_path() -> std::path::PathBuf {
        let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "turntable-schema-test-{}-{sequence}.json",
            std::process::id()
        ))
    }

    fn generator_for_template(path: &Path) -> Generator {
        let toml = format!(
            r#"
template = "{}"
target_version = "1.14.0-beta.2"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#,
            path.display()
        );
        Generator::new(GeneratorConfig::from_toml(&toml).unwrap())
    }

    #[tokio::test]
    async fn latest_template_loading_uses_schema_and_preserves_beta_2_fields() {
        let path = temporary_template_path();
        std::fs::write(
            &path,
            r#"{
              "route": {
                "rule_set": [{
                  "type": "remote",
                  "tag": "remote",
                  "format": "source",
                  "url": "https://example.com/rules.json",
                  "initial_path": "/bootstrap"
                }]
              }
            }"#,
        )
        .unwrap();

        let document = generator_for_template(&path).load_template().await.unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(
            document.to_value()["route"]["rule_set"][0]["initial_path"],
            "/bootstrap"
        );
    }

    #[tokio::test]
    async fn latest_template_loading_rejects_fields_outside_the_schema() {
        let path = temporary_template_path();
        std::fs::write(&path, r#"{"future_top_level": true}"#).unwrap();

        let error = generator_for_template(&path)
            .load_template()
            .await
            .unwrap_err();
        std::fs::remove_file(path).unwrap();

        assert!(error.to_string().contains("official sing-box schema"));
        assert!(format!("{error:#}").contains("future_top_level"));
    }

    #[test]
    fn test_parse_full_generator_config() {
        let config = GeneratorConfig::from_toml(EXAMPLE_GENERATOR_TOML).unwrap();

        assert_eq!(config.template, "./templates/1.13.json");
        assert_eq!(config.output, "./out/config.json");
        assert!(!config.ipv4_only);
        assert_eq!(config.target_version, "1.13");
        assert!(config.country_code_outbound_selectors);
        assert!(!config.no_detour);
        assert!(!config.detour_selector);
        assert!(!config.cache_subscription);
        assert_eq!(config.cache_ttl, 60);
        assert!(!config.diff_subscription);
        assert!(config.sing_box_binary.is_none());
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].name, "MyProvider");
        assert_eq!(
            config.subscriptions[0].url,
            "https://example.com/subscription-url"
        );
    }

    #[test]
    fn test_parse_minimal_generator_config() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();

        assert_eq!(config.template, "./template.json");
        // Check defaults
        assert_eq!(config.output, "./out/config.json");
        assert!(!config.ipv4_only);
        assert_eq!(config.target_version, "1.14.0-beta.2");
        assert_eq!(config.resolved_target_version(), "1.14.0-beta.2");
        assert!(config.get_schema_bundle().is_some());
        assert!(config.country_code_outbound_selectors);
        assert!(!config.no_detour);
        assert!(!config.detour_selector);
        assert!(!config.cache_subscription);
        assert_eq!(config.cache_ttl, 60);
        assert!(!config.diff_subscription);
        assert!(config.sing_box_binary.is_none());
        assert_eq!(config.subscriptions.len(), 1);
    }

    #[test]
    fn test_parse_native_sing_box_binary() {
        let toml = r#"
template = "./template.json"
sing_box_binary = "/opt/sing-box/bin/sing-box"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.sing_box_binary.as_deref(),
            Some("/opt/sing-box/bin/sing-box")
        );
    }

    #[test]
    fn test_empty_native_sing_box_binary_fails() {
        let toml = r#"
template = "./template.json"
sing_box_binary = " "

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let error = GeneratorConfig::from_toml(toml).unwrap_err();
        assert!(error.to_string().contains("sing_box_binary"));
    }

    #[test]
    fn test_parse_multiple_subscriptions() {
        let toml = r#"
template = "./template.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"

[[subscriptions]]
name = "Provider2"
url = "https://example.com/sub2"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(config.subscriptions.len(), 2);
        assert_eq!(config.subscriptions[0].name, "Provider1");
        assert_eq!(config.subscriptions[1].name, "Provider2");
    }

    #[test]
    fn test_parse_no_subscriptions_fails() {
        let toml = r#"
template = "./template.json"
subscriptions = []
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("At least one subscription is required")
        );
    }

    #[test]
    fn test_parse_missing_template_fails() {
        let toml = r#"
[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_singbox_subscription() {
        let json = r#"{
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ]
        }"#;
        let sub: SingBoxSubscription = serde_json::from_str(json).unwrap();
        assert_eq!(sub.outbounds.len(), 2);
    }

    #[test]
    fn test_parse_singbox_subscription_empty() {
        let json = r#"{"outbounds": []}"#;
        let sub: SingBoxSubscription = serde_json::from_str(json).unwrap();
        assert!(sub.outbounds.is_empty());
    }

    #[test]
    fn test_parse_singbox_subscription_no_outbounds_field() {
        let json = r#"{}"#;
        let sub: SingBoxSubscription = serde_json::from_str(json).unwrap();
        assert!(sub.outbounds.is_empty());
    }

    #[test]
    fn test_expand_tilde() {
        let path = "~/config/test.toml";
        let expanded = expand_tilde(path);
        // Should not start with ~ anymore if home is set
        if helpers::dirs_home().is_some() {
            assert!(!expanded.starts_with("~/"));
        }
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let path = "./config/test.toml";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_expand_tilde_absolute_path() {
        let path = "/etc/config/test.toml";
        let expanded = expand_tilde(path);
        assert_eq!(expanded, path);
    }

    // ========================================================================
    // Target Version Tests
    // ========================================================================

    #[test]
    fn test_parse_valid_target_versions() {
        let toml_1_10 = r#"
template = "./template.json"
target_version = "1.10"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_1_10).unwrap();
        assert_eq!(config.target_version, "1.10");
        let version = config.get_target_version();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 10);

        let toml_1_11 = r#"
template = "./template.json"
target_version = "1.11"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_1_11).unwrap();
        assert_eq!(config.target_version, "1.11");

        let toml_1_12 = r#"
template = "./template.json"
target_version = "1.12"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_1_12).unwrap();
        assert_eq!(config.target_version, "1.12");

        let toml_schema_release = r#"
template = "./template.json"
target_version = "1.14.0-beta.2"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_schema_release).unwrap();
        assert_eq!(config.target_version, "1.14.0-beta.2");
        assert_eq!(config.resolved_target_version(), "1.14.0-beta.2");
        let version = config.get_target_version();
        assert_eq!(version.patch, Some(0));

        let toml_alias = r#"
template = "./template.json"
target_version = "1.14"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_alias).unwrap();
        assert_eq!(config.target_version, "1.14");
        assert_eq!(config.resolved_target_version(), "1.14.0-beta.2");
        assert!(crate::config::schema::is_alias(&config.target_version));
    }

    #[test]
    fn test_rejects_unbundled_schema_release() {
        let toml = r#"
template = "./template.json"
target_version = "1.14.0-beta.3"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let error = GeneratorConfig::from_toml(toml).unwrap_err().to_string();
        assert!(error.contains("No bundled schema"));
        assert!(error.contains("1.14.0-beta.2"));

        let stable_toml = toml.replace("1.14.0-beta.3", "1.14.0");
        let error = GeneratorConfig::from_toml(&stable_toml)
            .unwrap_err()
            .to_string();
        assert!(error.contains("No bundled schema"));
    }

    #[test]
    fn test_parse_invalid_target_version_below_minimum() {
        let toml = r#"
template = "./template.json"
target_version = "1.9"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid target_version"),
            "Expected 'Invalid target_version' in error: {}",
            err
        );
        assert!(
            err.contains("below minimum"),
            "Expected 'below minimum' in error: {}",
            err
        );
    }

    #[test]
    fn test_parse_invalid_target_version_above_maximum() {
        let toml = r#"
template = "./template.json"
target_version = "1.99"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Invalid target_version"),
            "Expected 'Invalid target_version' in error: {}",
            err
        );
        assert!(
            err.contains("above latest"),
            "Expected 'above latest' in error: {}",
            err
        );
    }

    #[test]
    fn test_parse_invalid_target_version_format() {
        let toml = r#"
template = "./template.json"
target_version = "invalid"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid target_version"));
    }

    #[test]
    fn test_default_target_version() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert_eq!(config.target_version, "1.14.0-beta.2");
        let version = config.get_target_version();
        assert_eq!(version, SingBoxVersion::latest());
    }

    #[test]
    fn test_get_target_version() {
        let toml = r#"
template = "./template.json"
target_version = "1.11"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        let version = config.get_target_version();

        // Check feature detection works
        assert!(version.supports_endpoints());
        assert!(version.supports_hysteria2_port_hopping());
        assert!(!version.supports_services());
        assert!(!version.supports_certificate());
        assert!(version.supports_legacy_dns());
        assert!(version.supports_geoip_geosite());
    }

    // ========================================================================
    // IPv4 Only and Country Code Selectors Tests
    // ========================================================================

    #[test]
    fn test_parse_ipv4_only_enabled() {
        let toml = r#"
template = "./template.json"
ipv4_only = true

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.ipv4_only);
    }

    #[test]
    fn test_parse_ipv4_only_default_false() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(!config.ipv4_only);
    }

    #[test]
    fn test_parse_country_code_outbound_selectors_disabled() {
        let toml = r#"
template = "./template.json"
country_code_outbound_selectors = false

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(!config.country_code_outbound_selectors);
    }

    #[test]
    fn test_parse_country_code_outbound_selectors_default_true() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(config.country_code_outbound_selectors);
    }

    #[test]
    fn test_parse_multiple_subscriptions_for_selectors() {
        let toml = r#"
template = "./template.json"
country_code_outbound_selectors = true

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"

[[subscriptions]]
name = "Provider2"
url = "https://example.com/sub2"

[[subscriptions]]
name = "Provider3"
url = "https://example.com/sub3"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(config.subscriptions.len(), 3);
        assert_eq!(config.subscriptions[0].name, "Provider1");
        assert_eq!(config.subscriptions[1].name, "Provider2");
        assert_eq!(config.subscriptions[2].name, "Provider3");
    }

    #[test]
    fn test_parse_country_codes_specified() {
        let toml = r#"
template = "./template.json"
country_codes = ["US", "JP", "HK"]

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(config.country_codes.len(), 3);
        assert_eq!(config.country_codes[0], "US");
        assert_eq!(config.country_codes[1], "JP");
        assert_eq!(config.country_codes[2], "HK");
    }

    #[test]
    fn test_parse_country_codes_empty() {
        let toml = r#"
template = "./template.json"
country_codes = []

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.country_codes.is_empty());
    }

    #[test]
    fn test_parse_country_codes_default_empty() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(config.country_codes.is_empty());
    }

    // ========================================================================
    // Detour Selector Tests
    // ========================================================================

    #[test]
    fn test_parse_detour_selector_enabled() {
        let toml = r#"
template = "./template.json"
detour_selector = true

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.detour_selector);
        assert!(!config.no_detour);
    }

    #[test]
    fn test_parse_detour_selector_default_false() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(!config.detour_selector);
    }

    #[test]
    fn test_parse_no_detour_enabled() {
        let toml = r#"
template = "./template.json"
no_detour = true

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.no_detour);
        assert!(!config.detour_selector);
    }

    // ========================================================================
    // Cache Subscription Tests
    // ========================================================================

    #[test]
    fn test_parse_cache_subscription_enabled() {
        let toml = r#"
template = "./template.json"
cache_subscription = true
cache_ttl = 120

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.cache_subscription);
        assert_eq!(config.cache_ttl, 120);
    }

    #[test]
    fn test_parse_cache_subscription_default_false() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(!config.cache_subscription);
        assert_eq!(config.cache_ttl, 60);
    }

    #[test]
    fn test_parse_cache_ttl_custom() {
        let toml = r#"
template = "./template.json"
cache_subscription = true
cache_ttl = 30

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.cache_subscription);
        assert_eq!(config.cache_ttl, 30);
    }

    #[test]
    fn test_parse_diff_subscription_enabled() {
        let toml = r#"
template = "./template.json"
diff_subscription = true

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.diff_subscription);
    }

    #[test]
    fn test_parse_diff_subscription_default_false() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(!config.diff_subscription);
    }

    #[test]
    fn test_diff_outbounds_no_changes() {
        use crate::config::outbound::SocksOutbound;

        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        let generator = Generator::new(config);

        let old = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "5.6.7.8", 1080)),
        ];
        let new = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "5.6.7.8", 1080)),
        ];

        // This should not panic and should log "No changes"
        generator.diff_outbounds("TestSub", &old, &new);
    }

    #[test]
    fn test_diff_outbounds_with_additions() {
        use crate::config::outbound::SocksOutbound;

        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        let generator = Generator::new(config);

        let old = vec![Outbound::Socks(SocksOutbound::new(
            "proxy1", "1.2.3.4", 1080,
        ))];
        let new = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "5.6.7.8", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy3", "9.10.11.12", 1080)),
        ];

        // This should log additions
        generator.diff_outbounds("TestSub", &old, &new);
    }

    #[test]
    fn test_diff_outbounds_with_removals() {
        use crate::config::outbound::SocksOutbound;

        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        let generator = Generator::new(config);

        let old = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "5.6.7.8", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy3", "9.10.11.12", 1080)),
        ];
        let new = vec![Outbound::Socks(SocksOutbound::new(
            "proxy1", "1.2.3.4", 1080,
        ))];

        // This should log removals
        generator.diff_outbounds("TestSub", &old, &new);
    }

    #[test]
    fn test_diff_outbounds_with_both() {
        use crate::config::outbound::SocksOutbound;

        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        let generator = Generator::new(config);

        let old = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy2", "5.6.7.8", 1080)),
        ];
        let new = vec![
            Outbound::Socks(SocksOutbound::new("proxy1", "1.2.3.4", 1080)),
            Outbound::Socks(SocksOutbound::new("proxy3", "9.10.11.12", 1080)),
        ];

        // This should log both additions and removals
        generator.diff_outbounds("TestSub", &old, &new);
    }

    // ========================================================================
    // Subscription Filter Tests
    // ========================================================================

    #[test]
    fn test_parse_subscription_with_filter() {
        let toml = r#"
template = "./template.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
filter = [0, 1, 2]
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(config.subscriptions.len(), 1);
        assert_eq!(config.subscriptions[0].filter, vec![0, 1, 2]);
    }

    #[test]
    fn test_parse_subscription_filter_empty() {
        let toml = r#"
template = "./template.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
filter = []
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.subscriptions[0].filter.is_empty());
    }

    #[test]
    fn test_parse_subscription_filter_default_empty() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(config.subscriptions[0].filter.is_empty());
    }

    #[test]
    fn test_parse_multiple_subscriptions_with_different_filters() {
        let toml = r#"
template = "./template.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
filter = [0]

[[subscriptions]]
name = "Provider2"
url = "https://example.com/sub2"
filter = [1, 2, 3]

[[subscriptions]]
name = "Provider3"
url = "https://example.com/sub3"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert_eq!(config.subscriptions.len(), 3);
        assert_eq!(config.subscriptions[0].filter, vec![0]);
        assert_eq!(config.subscriptions[1].filter, vec![1, 2, 3]);
        assert!(config.subscriptions[2].filter.is_empty());
    }

    // ========================================================================
    // WebDAV Configuration Tests
    // ========================================================================

    #[test]
    fn test_parse_webdav_config_enabled() {
        let toml = r#"
template = "./template.json"
webdav_upload = true
webdav_url = "https://example.com/dav"
webdav_username = "user"
webdav_password = "secret"
upload_path = "/configs/sing-box.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.webdav_upload);
        assert_eq!(config.webdav_url, "https://example.com/dav");
        assert_eq!(config.webdav_username, "user");
        assert_eq!(config.webdav_password, "secret");
        assert_eq!(config.upload_path, "/configs/sing-box.json");

        // Test get_webdav_config method
        let webdav_config = config.get_webdav_config();
        assert!(webdav_config.webdav_upload);
        assert_eq!(webdav_config.webdav_url, "https://example.com/dav");
        assert!(webdav_config.is_configured());
    }

    #[test]
    fn test_parse_webdav_config_default_disabled() {
        let config = GeneratorConfig::from_toml(MINIMAL_GENERATOR_TOML).unwrap();
        assert!(!config.webdav_upload);
        assert!(config.webdav_url.is_empty());
        assert!(config.webdav_username.is_empty());
        assert!(config.webdav_password.is_empty());
        assert!(config.upload_path.is_empty());

        let webdav_config = config.get_webdav_config();
        assert!(!webdav_config.is_configured());
    }

    #[test]
    fn test_parse_webdav_config_missing_url_fails() {
        let toml = r#"
template = "./template.json"
webdav_upload = true
upload_path = "/configs/sing-box.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("WebDAV URL is required"));
    }

    #[test]
    fn test_parse_webdav_config_missing_path_fails() {
        let toml = r#"
template = "./template.json"
webdav_upload = true
webdav_url = "https://example.com/dav"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Upload path is required"));
    }

    #[test]
    fn test_parse_webdav_config_invalid_url_fails() {
        let toml = r#"
template = "./template.json"
webdav_upload = true
webdav_url = "ftp://example.com/dav"
upload_path = "/configs/sing-box.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let result = GeneratorConfig::from_toml(toml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must start with http://"));
    }

    #[test]
    fn test_parse_webdav_config_without_auth() {
        let toml = r#"
template = "./template.json"
webdav_upload = true
webdav_url = "https://example.com/dav"
upload_path = "/configs/sing-box.json"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml).unwrap();
        assert!(config.webdav_upload);
        assert!(config.webdav_username.is_empty());
        assert!(config.webdav_password.is_empty());

        let webdav_config = config.get_webdav_config();
        assert!(webdav_config.is_configured());
    }
}

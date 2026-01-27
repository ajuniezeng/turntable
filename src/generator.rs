use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::SingBoxConfig;
use crate::config::dns::{Dns, Strategy};
use crate::config::outbound::Outbound;
use crate::config::version::{LATEST_VERSION, SingBoxVersion};
use crate::parser::{SubscriptionType, detect_subscription_type, parse_subscription};
use crate::transform::{
    filter_ipv6_outbounds, generate_country_code_selectors_filtered,
    generate_subscription_selector, get_outbound_tag, update_selectors_with_new_tags,
};

// ============================================================================
// Generator Config Types
// ============================================================================

/// Generator configuration parsed from TOML file
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeneratorConfig {
    /// Template file path or URL (required)
    pub template: String,

    /// Output file path, default "./out/config.json"
    #[serde(default = "default_output")]
    pub output: String,

    /// DNS strategy will be set to `ipv4_only`, remove all outbound whose host is IPv6 address
    #[serde(default)]
    pub ipv4_only: bool,

    /// Target sing-box version, default to latest supported version
    #[serde(default = "default_target_version")]
    pub target_version: String,

    /// Enable country code outbound selectors
    #[serde(default = "default_true")]
    pub country_code_outbound_selectors: bool,

    /// List of country codes to include in selectors (e.g., ["US", "JP", "HK"])
    /// If empty or not specified, all country codes found in outbound tags will be included
    #[serde(default)]
    pub country_codes: Vec<String>,

    /// Remove outbound with detour tags
    #[serde(default)]
    pub no_detour: bool,

    /// Subscriptions list (required - at least one)
    pub subscriptions: Vec<Subscription>,
}

/// Subscription configuration
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Subscription {
    /// Name/identifier for this subscription
    pub name: String,

    /// URL to fetch the subscription from
    pub url: String,
}

fn default_output() -> String {
    "./out/config.json".to_string()
}

fn default_target_version() -> String {
    format!("{}.{}", LATEST_VERSION.0, LATEST_VERSION.1)
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Sing-box Subscription Format
// ============================================================================

/// Sing-box format subscription response
/// Contains only outbounds array
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingBoxSubscription {
    /// Outbound configurations from subscription
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
}

// ============================================================================
// Generator Implementation
// ============================================================================

impl GeneratorConfig {
    /// Parse generator config from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        let config: GeneratorConfig =
            toml::from_str(content).context("Failed to parse generator config TOML")?;

        // Validate required fields
        if config.subscriptions.is_empty() {
            anyhow::bail!("At least one subscription is required");
        }

        // Validate target_version
        SingBoxVersion::from_str(&config.target_version).map_err(|e| {
            anyhow::anyhow!("Invalid target_version: {}: {}", config.target_version, e)
        })?;

        Ok(config)
    }

    /// Get the parsed target version.
    pub fn get_target_version(&self) -> SingBoxVersion {
        // Safe to unwrap because we validated in from_toml
        SingBoxVersion::from_str(&self.target_version).unwrap_or_else(|_| SingBoxVersion::latest())
    }

    /// Load generator config from file path
    pub async fn from_file(path: &Path) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read generator config from {:?}", path))?;
        Self::from_toml(&content)
    }

    /// Load generator config from file path or URL
    pub async fn load(path_or_url: &str) -> Result<Self> {
        if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            Self::from_url(path_or_url).await
        } else {
            // Expand ~ to home directory
            let expanded = expand_tilde(path_or_url);
            Self::from_file(Path::new(&expanded)).await
        }
    }

    /// Load generator config from URL
    pub async fn from_url(url: &str) -> Result<Self> {
        let content = fetch_text(url).await?;
        Self::from_toml(&content)
    }
}

/// Generator that orchestrates the config generation process
pub struct Generator {
    config: GeneratorConfig,
}

impl Generator {
    /// Create a new generator with the given config
    pub fn new(config: GeneratorConfig) -> Self {
        Self { config }
    }

    /// Load generator from path or URL
    pub async fn load(path_or_url: &str) -> Result<Self> {
        let config = GeneratorConfig::load(path_or_url).await?;
        Ok(Self::new(config))
    }

    /// Run the generation process
    pub async fn generate(&self) -> Result<SingBoxConfig> {
        info!("Starting config generation");

        // 1. Load template
        let mut config = self.load_template().await?;
        debug!("Loaded template with {} outbounds", config.outbounds.len());

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
            let dns = config.dns.get_or_insert_with(Dns::default);
            dns.strategy = Some(Strategy::Ipv4Only);
            debug!("Set DNS strategy to ipv4_only");

            subscriptions_with_outbounds
                .into_iter()
                .map(|(name, outbounds)| (name, filter_ipv6_outbounds(outbounds)))
                .collect()
        } else {
            subscriptions_with_outbounds
        };

        // 4. Collect all subscription outbounds for country code processing
        let all_subscription_outbounds: Vec<Outbound> = subscriptions_with_outbounds
            .iter()
            .flat_map(|(_, outbounds)| outbounds.clone())
            .collect();

        // 5. Generate subscription selectors (one per subscription)
        let subscription_selectors: Vec<Outbound> = subscriptions_with_outbounds
            .iter()
            .map(|(name, outbounds)| generate_subscription_selector(name, outbounds))
            .collect();
        info!(
            "Generated {} subscription selectors",
            subscription_selectors.len()
        );

        // 6. Generate country code selectors if enabled
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

        // 7. Collect all new selector tags for updating template selectors
        // Order: subscription selectors first, then country code selectors (alphabetically sorted)
        let new_selector_tags: Vec<String> = subscription_selectors
            .iter()
            .chain(country_selectors.iter())
            .filter_map(|o| get_outbound_tag(o).map(|s| s.to_string()))
            .collect();

        // 8. Update existing selectors in template with new selector tags
        if !new_selector_tags.is_empty() {
            debug!(
                "Updating template selectors with {} new tags",
                new_selector_tags.len()
            );
            update_selectors_with_new_tags(&mut config.outbounds, &new_selector_tags);
        }

        // 9. Add all new outbounds to config:
        //    - Subscription selectors
        //    - Country code selectors
        //    - All subscription outbounds
        config.outbounds.extend(subscription_selectors);
        config.outbounds.extend(country_selectors);
        config.outbounds.extend(all_subscription_outbounds);

        info!("Final config has {} outbounds", config.outbounds.len());

        Ok(config)
    }

    /// Generate and write to output file
    pub async fn generate_to_file(&self, output_override: Option<&str>) -> Result<()> {
        let config = self.generate().await?;

        // Get target version for validation
        let target_version = self.config.get_target_version();
        info!("Validating config for sing-box version {}", target_version);

        // Validate the generated config against target version and log any warnings/errors
        let validation_result = config.validate_for_version(&target_version);
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

        let output_path = output_override.unwrap_or(&self.config.output);
        let expanded_path = expand_tilde(output_path);
        let path = Path::new(&expanded_path);

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create output directory {:?}", parent))?;
        }

        // Serialize to pretty JSON
        let json = config
            .to_json_pretty()
            .context("Failed to serialize config to JSON")?;

        // Write to file
        tokio::fs::write(path, &json)
            .await
            .with_context(|| format!("Failed to write config to {:?}", path))?;

        info!("Config written to {:?}", path);
        Ok(())
    }

    /// Load the template configuration
    async fn load_template(&self) -> Result<SingBoxConfig> {
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

        let config = SingBoxConfig::from_json(&content)
            .context("Failed to parse template as sing-box config")?;

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
            info!(
                "Fetching subscription [{}/{}]: '{}' from {}",
                index + 1,
                total_subscriptions,
                sub.name,
                sub.url
            );

            match self.fetch_singbox_subscription(&sub.url).await {
                Ok(outbounds) => {
                    info!(
                        "Subscription '{}' returned {} outbounds",
                        sub.name,
                        outbounds.len()
                    );
                    for outbound in &outbounds {
                        let tag = crate::transform::get_outbound_tag(outbound)
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
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Fetch text content from a URL
async fn fetch_text(url: &str) -> Result<String> {
    debug!("Fetching URL: {}", url);

    let client = reqwest::Client::builder()
        .user_agent("turntable/0.1.0")
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

/// Expand ~ to home directory in path
fn expand_tilde(path: &str) -> String {
    if (path.starts_with("~/") || path == "~")
        && let Some(home) = dirs_home()
    {
        return path.replacen("~", &home, 1);
    }
    path.to_string()
}

/// Get home directory path
fn dirs_home() -> Option<String> {
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_GENERATOR_TOML: &str = r#"
template = "./templates/1.13.json"
output = "./out/config.json"
ipv4_only = false
target_version = "1.13"
country_code_outbound_selectors = true
no_detour = false

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

    #[test]
    fn test_parse_full_generator_config() {
        let config = GeneratorConfig::from_toml(EXAMPLE_GENERATOR_TOML).unwrap();

        assert_eq!(config.template, "./templates/1.13.json");
        assert_eq!(config.output, "./out/config.json");
        assert!(!config.ipv4_only);
        assert_eq!(config.target_version, "1.13");
        assert!(config.country_code_outbound_selectors);
        assert!(!config.no_detour);
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
        assert_eq!(config.target_version, "1.13");
        assert!(config.country_code_outbound_selectors);
        assert!(!config.no_detour);
        assert_eq!(config.subscriptions.len(), 1);
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
        if dirs_home().is_some() {
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

        let toml_with_patch = r#"
template = "./template.json"
target_version = "1.13.5"

[[subscriptions]]
name = "Provider1"
url = "https://example.com/sub1"
"#;
        let config = GeneratorConfig::from_toml(toml_with_patch).unwrap();
        assert_eq!(config.target_version, "1.13.5");
        let version = config.get_target_version();
        assert_eq!(version.patch, Some(5));
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
        assert_eq!(config.target_version, "1.13");
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
}

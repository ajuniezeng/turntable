use std::{path::Path, str::FromStr};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    config::schema::{self, SCHEMA_VERSION, SchemaBundle},
    config::version::{LATEST_VERSION, SingBoxVersion},
    webdav::WebDavConfig,
};

use super::helpers::{expand_tilde, fetch_text};
use super::subscription::Subscription;

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

    /// Remove outbounds with detour tags
    #[serde(default)]
    pub no_detour: bool,

    /// Create a detour selector with all non-detour outbounds and replace detour tags with this selector.
    /// Only works when `no_detour` is false.
    #[serde(default)]
    pub detour_selector: bool,

    /// Cache every subscription as a single sing-box outbound format json file in output directory
    #[serde(default)]
    pub cache_subscription: bool,

    /// Cache time to live in minutes. Ignored when `cache_subscription` is false.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// Show diff between newly fetched subscription and cached version
    #[serde(default)]
    pub diff_subscription: bool,

    /// Optional sing-box binary used for authoritative native validation.
    ///
    /// The configured binary must match the target release and build tags.
    #[serde(default)]
    pub sing_box_binary: Option<String>,

    /// Enable WebDAV upload
    #[serde(default)]
    pub webdav_upload: bool,

    /// WebDAV server URL (e.g., "https://example.com/dav")
    #[serde(default)]
    pub webdav_url: String,

    /// WebDAV username for authentication
    #[serde(default)]
    pub webdav_username: String,

    /// WebDAV password for authentication
    #[serde(default)]
    pub webdav_password: String,

    /// Remote path where the config will be uploaded (e.g., "/path/to/config.json")
    #[serde(default)]
    pub upload_path: String,

    /// Subscriptions list (required - at least one)
    pub subscriptions: Vec<Subscription>,
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

        validate_target_version(&config.target_version)?;

        if config
            .sing_box_binary
            .as_deref()
            .is_some_and(|binary| binary.trim().is_empty())
        {
            anyhow::bail!("sing_box_binary must not be empty");
        }

        // Validate WebDAV config if enabled
        config.get_webdav_config().validate()?;

        Ok(config)
    }

    /// Get the WebDAV configuration from generator config fields
    pub fn get_webdav_config(&self) -> WebDavConfig {
        WebDavConfig {
            webdav_upload: self.webdav_upload,
            webdav_url: self.webdav_url.clone(),
            webdav_username: self.webdav_username.clone(),
            webdav_password: self.webdav_password.clone(),
            upload_path: self.upload_path.clone(),
        }
    }

    /// Get the parsed target version.
    pub fn get_target_version(&self) -> SingBoxVersion {
        if let Some(bundle) = self.get_schema_bundle() {
            let numeric_release = bundle
                .release()
                .split_once('-')
                .map_or(bundle.release(), |(numeric, _)| numeric);
            let components = numeric_release
                .split('.')
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("registered schema releases must start with a numeric version");
            return match components.as_slice() {
                [major, minor] => SingBoxVersion::new(*major, *minor),
                [major, minor, patch] => SingBoxVersion::with_patch(*major, *minor, *patch),
                _ => panic!("registered schema releases must use MAJOR.MINOR[.PATCH]"),
            };
        }

        SingBoxVersion::from_str(&self.target_version)
            .expect("generator target_version is validated during parsing")
    }

    /// Return the schema selected by this target, if it is schema-backed.
    pub fn get_schema_bundle(&self) -> Option<&'static SchemaBundle> {
        schema::for_target(&self.target_version)
    }

    /// Return the canonical target release after resolving aliases.
    pub fn resolved_target_version(&self) -> &str {
        self.get_schema_bundle()
            .map_or_else(|| self.target_version.trim(), |bundle| bundle.release())
    }

    /// Return whether this target is accepted only for legacy compatibility.
    pub fn is_target_version_deprecated(&self) -> bool {
        self.get_target_version().is_deprecated()
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

fn default_output() -> String {
    "./out/config.json".to_string()
}

fn default_target_version() -> String {
    SCHEMA_VERSION.to_string()
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    60
}

fn validate_target_version(target: &str) -> Result<()> {
    if schema::for_target(target).is_some() {
        return Ok(());
    }

    match SingBoxVersion::from_str(target) {
        Ok(version) if version.major == 1 && version.minor >= LATEST_VERSION.1 => {
            let releases = schema::supported_releases().collect::<Vec<_>>().join(", ");
            anyhow::bail!(
                "No bundled schema for target_version '{}'; available schema releases: {}",
                target.trim(),
                releases
            );
        }
        Ok(_) => Ok(()),
        Err(error) => {
            let numeric_prefix = target.trim().split_once('-').map(|(numeric, _)| numeric);
            if numeric_prefix
                .and_then(|numeric| SingBoxVersion::from_str(numeric).ok())
                .is_some_and(|version| version.major == 1 && version.minor >= LATEST_VERSION.1)
            {
                let releases = schema::supported_releases().collect::<Vec<_>>().join(", ");
                anyhow::bail!(
                    "No bundled schema for target_version '{}'; available schema releases: {}",
                    target.trim(),
                    releases
                );
            }

            Err(anyhow::anyhow!(
                "Invalid target_version: {}: {}",
                target,
                error
            ))
        }
    }
}

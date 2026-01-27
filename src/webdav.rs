//! WebDAV client implementation for uploading configuration files.
//!
//! This module provides functionality to upload files to WebDAV servers
//! with support for basic authentication and directory creation.

use anyhow::{Context, Result};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::get_version;

/// Default filename to use when upload_path is a directory
const DEFAULT_FILENAME: &str = "config.json";

/// WebDAV configuration for uploading generated config files
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WebDavConfig {
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
    /// If the path ends with '/', a default filename "config.json" will be appended.
    #[serde(default)]
    pub upload_path: String,
}

impl WebDavConfig {
    /// Check if WebDAV upload is enabled and properly configured
    pub fn is_configured(&self) -> bool {
        self.webdav_upload && !self.webdav_url.is_empty() && !self.upload_path.is_empty()
    }

    /// Validate the WebDAV configuration
    pub fn validate(&self) -> Result<()> {
        if !self.webdav_upload {
            return Ok(());
        }

        if self.webdav_url.is_empty() {
            anyhow::bail!("WebDAV URL is required when webdav_upload is enabled");
        }

        if self.upload_path.is_empty() {
            anyhow::bail!("Upload path is required when webdav_upload is enabled");
        }

        // Validate URL format
        if !self.webdav_url.starts_with("http://") && !self.webdav_url.starts_with("https://") {
            anyhow::bail!("WebDAV URL must start with http:// or https://");
        }

        Ok(())
    }

    /// Get the normalized upload path, appending default filename if path is a directory
    pub fn get_normalized_upload_path(&self) -> String {
        let path = self.upload_path.trim();
        if path.ends_with('/') {
            format!("{}{}", path, DEFAULT_FILENAME)
        } else if path.is_empty() {
            format!("/{}", DEFAULT_FILENAME)
        } else {
            path.to_string()
        }
    }
}

/// WebDAV client for uploading files
pub struct WebDavClient {
    client: Client,
    config: WebDavConfig,
}

impl WebDavClient {
    /// Create a new WebDAV client with the given configuration
    pub fn new(config: WebDavConfig) -> Result<Self> {
        config.validate()?;

        let client = Client::builder()
            .user_agent(format!("turntable/{}", get_version()))
            .build()
            .context("Failed to build HTTP client for WebDAV")?;

        Ok(Self { client, config })
    }

    /// Build the full URL for the upload path
    fn build_url(&self, path: &str) -> String {
        let base_url = self.config.webdav_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            base_url.to_string()
        } else {
            format!("{}/{}", base_url, path)
        }
    }

    /// Create a request builder with authentication if credentials are provided
    fn request(&self, method: Method, url: &str) -> reqwest::RequestBuilder {
        let mut builder = self.client.request(method, url);

        // Add basic auth if credentials are provided
        if !self.config.webdav_username.is_empty() {
            builder = builder.basic_auth(
                &self.config.webdav_username,
                Some(&self.config.webdav_password),
            );
        }

        builder
    }

    /// Check if a resource exists using HEAD request
    async fn resource_exists(&self, url: &str) -> Result<bool> {
        debug!("Checking if resource exists: {}", url);

        let response = self
            .request(Method::HEAD, url)
            .send()
            .await
            .with_context(|| format!("Failed to check resource: {}", url))?;

        let status = response.status();
        debug!("HEAD response status: {}", status);

        Ok(status.is_success())
    }

    /// Delete a resource using DELETE request (used before replacing)
    async fn delete_resource(&self, url: &str) -> Result<bool> {
        debug!("Deleting resource: {}", url);

        let response = self
            .request(Method::DELETE, url)
            .send()
            .await
            .with_context(|| format!("Failed to delete resource: {}", url))?;

        let status = response.status();
        debug!("DELETE response status: {}", status);

        match status {
            StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(true),
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!("WebDAV authentication failed for DELETE");
            }
            StatusCode::FORBIDDEN => {
                anyhow::bail!("WebDAV access forbidden for DELETE");
            }
            _ => {
                warn!(
                    "DELETE returned unexpected status {}, continuing anyway",
                    status
                );
                Ok(false)
            }
        }
    }

    /// Upload content to the WebDAV server using PUT method
    pub async fn upload(&self, content: &str) -> Result<()> {
        let upload_path = self.config.get_normalized_upload_path();
        let url = self.build_url(&upload_path);
        info!("Uploading config to WebDAV: {}", url);

        // First, try to create parent directories
        if let Err(e) = self.ensure_parent_directories(&upload_path).await {
            warn!("Failed to create parent directories: {}", e);
            // Continue anyway, the server might already have the directories
        }

        // Try PUT request first
        match self.put_content(&url, content).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Check if it's a 405 error, which might mean we need to DELETE first
                let err_str = e.to_string();
                if err_str.contains("405") || err_str.contains("Method Not Allowed") {
                    debug!("PUT failed with 405, trying DELETE then PUT");

                    // Check if resource exists
                    if self.resource_exists(&url).await.unwrap_or(false) {
                        // Try to delete existing resource
                        if let Err(del_err) = self.delete_resource(&url).await {
                            warn!("Failed to delete existing resource: {}", del_err);
                        }

                        // Retry PUT after delete
                        if self.put_content(&url, content).await.is_ok() {
                            return Ok(());
                        }
                    }

                    // If still failing, return original error with more context
                    anyhow::bail!(
                        "WebDAV upload failed. The server returned 405 Method Not Allowed. \
                        This might indicate:\n\
                        1. The upload_path points to a directory instead of a file\n\
                        2. The server doesn't support PUT on this path\n\
                        3. The server requires different permissions\n\
                        Current upload_path: {}\n\
                        Full URL: {}",
                        upload_path,
                        url
                    );
                }
                Err(e)
            }
        }
    }

    /// Perform the actual PUT request
    async fn put_content(&self, url: &str, content: &str) -> Result<()> {
        let response = self
            .request(Method::PUT, url)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Overwrite", "T") // WebDAV header to allow overwrite
            .body(content.to_string())
            .send()
            .await
            .with_context(|| format!("Failed to upload to WebDAV: {}", url))?;

        let status = response.status();
        debug!("WebDAV PUT response status: {}", status);

        match status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {
                info!("Successfully uploaded config to WebDAV: {}", url);
                Ok(())
            }
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!(
                    "WebDAV authentication failed. Please check your username and password."
                );
            }
            StatusCode::FORBIDDEN => {
                anyhow::bail!(
                    "WebDAV access forbidden. You may not have permission to write to this path."
                );
            }
            StatusCode::CONFLICT => {
                anyhow::bail!(
                    "WebDAV conflict. The parent directory may not exist. Path: {}",
                    url
                );
            }
            StatusCode::METHOD_NOT_ALLOWED => {
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "WebDAV upload failed with status 405 Method Not Allowed: {}",
                    if body.is_empty() {
                        "No response body".to_string()
                    } else {
                        body
                    }
                );
            }
            StatusCode::INSUFFICIENT_STORAGE => {
                anyhow::bail!("WebDAV server has insufficient storage space.");
            }
            StatusCode::LOCKED => {
                anyhow::bail!("WebDAV resource is locked. Please try again later.");
            }
            _ => {
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "WebDAV upload failed with status {}: {}",
                    status,
                    if body.is_empty() {
                        "No response body".to_string()
                    } else {
                        body
                    }
                );
            }
        }
    }

    /// Create a directory on the WebDAV server using MKCOL method
    async fn mkcol(&self, path: &str) -> Result<bool> {
        let url = self.build_url(path);
        debug!("Creating WebDAV directory: {}", url);

        let response = self
            .request(Method::from_bytes(b"MKCOL").unwrap(), &url)
            .send()
            .await
            .with_context(|| format!("Failed to create directory: {}", url))?;

        let status = response.status();
        debug!("WebDAV MKCOL response status: {}", status);

        match status {
            StatusCode::CREATED => {
                info!("Created WebDAV directory: {}", path);
                Ok(true)
            }
            // 405 Method Not Allowed often means the directory already exists
            // 301 Moved Permanently can also indicate the directory exists (some servers redirect)
            StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::CONFLICT
            | StatusCode::MOVED_PERMANENTLY => {
                debug!("Directory may already exist: {}", path);
                Ok(false)
            }
            StatusCode::UNAUTHORIZED => {
                anyhow::bail!("WebDAV authentication failed for MKCOL");
            }
            _ => {
                // Don't fail on MKCOL errors, just log them
                debug!(
                    "MKCOL returned status {} for path {}, continuing anyway",
                    status, path
                );
                Ok(false)
            }
        }
    }

    /// Ensure all parent directories exist for the given path
    async fn ensure_parent_directories(&self, path: &str) -> Result<()> {
        let path = path.trim_start_matches('/');
        let parts: Vec<&str> = path.split('/').collect();

        // Skip the last part (filename) and create directories for the rest
        if parts.len() <= 1 {
            return Ok(());
        }

        let mut current_path = String::new();
        for part in &parts[..parts.len() - 1] {
            if part.is_empty() {
                continue;
            }
            current_path = format!("{}/{}", current_path, part);
            self.mkcol(&current_path).await?;
        }

        Ok(())
    }
}

/// Upload content to WebDAV server if configured
///
/// This is a convenience function that creates a WebDAV client and uploads
/// the content in one call.
pub async fn upload_to_webdav(config: &WebDavConfig, content: &str) -> Result<()> {
    if !config.is_configured() {
        debug!("WebDAV upload is not configured, skipping");
        return Ok(());
    }

    let client = WebDavClient::new(config.clone())?;
    client.upload(content).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webdav_config_default() {
        let config = WebDavConfig::default();
        assert!(!config.webdav_upload);
        assert!(config.webdav_url.is_empty());
        assert!(config.webdav_username.is_empty());
        assert!(config.webdav_password.is_empty());
        assert!(config.upload_path.is_empty());
    }

    #[test]
    fn test_webdav_config_is_configured() {
        let mut config = WebDavConfig::default();
        assert!(!config.is_configured());

        config.webdav_upload = true;
        assert!(!config.is_configured());

        config.webdav_url = "https://example.com/dav".to_string();
        assert!(!config.is_configured());

        config.upload_path = "/path/to/config.json".to_string();
        assert!(config.is_configured());
    }

    #[test]
    fn test_webdav_config_validate_disabled() {
        let config = WebDavConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_webdav_config_validate_missing_url() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: String::new(),
            upload_path: "/path".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_webdav_config_validate_missing_path() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "https://example.com".to_string(),
            upload_path: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_webdav_config_validate_invalid_url() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "ftp://example.com".to_string(),
            upload_path: "/path".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_webdav_config_validate_success() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "https://example.com/dav".to_string(),
            webdav_username: "user".to_string(),
            webdav_password: "pass".to_string(),
            upload_path: "/path/to/config.json".to_string(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_get_normalized_upload_path_with_filename() {
        let config = WebDavConfig {
            upload_path: "/path/to/config.json".to_string(),
            ..Default::default()
        };
        assert_eq!(config.get_normalized_upload_path(), "/path/to/config.json");
    }

    #[test]
    fn test_get_normalized_upload_path_directory_with_slash() {
        let config = WebDavConfig {
            upload_path: "/path/to/".to_string(),
            ..Default::default()
        };
        assert_eq!(config.get_normalized_upload_path(), "/path/to/config.json");
    }

    #[test]
    fn test_get_normalized_upload_path_root_directory() {
        let config = WebDavConfig {
            upload_path: "/".to_string(),
            ..Default::default()
        };
        assert_eq!(config.get_normalized_upload_path(), "/config.json");
    }

    #[test]
    fn test_get_normalized_upload_path_empty() {
        let config = WebDavConfig {
            upload_path: String::new(),
            ..Default::default()
        };
        assert_eq!(config.get_normalized_upload_path(), "/config.json");
    }

    #[test]
    fn test_build_url() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "https://example.com/dav".to_string(),
            upload_path: "/path/to/config.json".to_string(),
            ..Default::default()
        };
        let client = WebDavClient::new(config).unwrap();

        assert_eq!(
            client.build_url("/path/to/config.json"),
            "https://example.com/dav/path/to/config.json"
        );
        assert_eq!(
            client.build_url("path/to/config.json"),
            "https://example.com/dav/path/to/config.json"
        );
    }

    #[test]
    fn test_build_url_trailing_slash() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "https://example.com/dav/".to_string(),
            upload_path: "/path/to/config.json".to_string(),
            ..Default::default()
        };
        let client = WebDavClient::new(config).unwrap();

        assert_eq!(
            client.build_url("/path/to/config.json"),
            "https://example.com/dav/path/to/config.json"
        );
    }

    #[test]
    fn test_build_url_empty_path() {
        let config = WebDavConfig {
            webdav_upload: true,
            webdav_url: "https://example.com/dav".to_string(),
            upload_path: "/test.json".to_string(),
            ..Default::default()
        };
        let client = WebDavClient::new(config).unwrap();

        assert_eq!(client.build_url(""), "https://example.com/dav");
        assert_eq!(client.build_url("/"), "https://example.com/dav");
    }

    #[test]
    fn test_webdav_config_serde() {
        let toml_str = r#"
            webdav_upload = true
            webdav_url = "https://example.com/dav"
            webdav_username = "user"
            webdav_password = "secret"
            upload_path = "/configs/sing-box.json"
        "#;

        let config: WebDavConfig = toml::from_str(toml_str).unwrap();
        assert!(config.webdav_upload);
        assert_eq!(config.webdav_url, "https://example.com/dav");
        assert_eq!(config.webdav_username, "user");
        assert_eq!(config.webdav_password, "secret");
        assert_eq!(config.upload_path, "/configs/sing-box.json");
    }

    #[test]
    fn test_webdav_config_serde_directory_path() {
        let toml_str = r#"
            webdav_upload = true
            webdav_url = "https://example.com/dav"
            upload_path = "/configs/"
        "#;

        let config: WebDavConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.upload_path, "/configs/");
        assert_eq!(config.get_normalized_upload_path(), "/configs/config.json");
    }
}

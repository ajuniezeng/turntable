use serde::{Deserialize, Serialize};

/// Certificate configuration for sing-box (since 1.12.0)
///
/// Configures the X509 trusted CA certificate list used for TLS connections.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Certificate {
    /// The default X509 trusted CA certificate list
    ///
    /// Available values:
    /// - `system` (default): System trusted CA certificates
    /// - `mozilla`: Mozilla Included List with China CA certificates removed
    /// - `chrome`: Chrome Root Store with China CA certificates removed (since 1.13.0)
    /// - `none`: Empty list
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<CertificateStore>,

    /// The certificate line array to trust, in PEM format
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate: Vec<String>,

    /// The paths to certificates to trust, in PEM format
    /// Will be automatically reloaded if file modified
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_path: Vec<String>,

    /// The directory paths to search for certificates to trust, in PEM format
    /// Will be automatically reloaded if file modified
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_directory_path: Vec<String>,
}

/// Certificate store type
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStore {
    /// System trusted CA certificates (default)
    System,
    /// Mozilla Included List with China CA certificates removed
    Mozilla,
    /// Chrome Root Store with China CA certificates removed (since 1.13.0)
    Chrome,
    /// Empty list
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_default_serializes_empty() {
        let cert = Certificate::default();
        let json = serde_json::to_string(&cert).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_certificate_store_serialization() {
        let store = CertificateStore::Mozilla;
        let json = serde_json::to_string(&store).unwrap();
        assert_eq!(json, r#""mozilla""#);

        let store = CertificateStore::Chrome;
        let json = serde_json::to_string(&store).unwrap();
        assert_eq!(json, r#""chrome""#);

        let store = CertificateStore::None;
        let json = serde_json::to_string(&store).unwrap();
        assert_eq!(json, r#""none""#);
    }

    #[test]
    fn test_certificate_with_store() {
        let cert = Certificate {
            store: Some(CertificateStore::Mozilla),
            ..Default::default()
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains(r#""store":"mozilla""#));
    }

    #[test]
    fn test_certificate_with_paths() {
        let cert = Certificate {
            certificate_path: vec!["/etc/ssl/certs/ca.pem".to_string()],
            certificate_directory_path: vec!["/etc/ssl/certs".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains(r#""certificate_path":["/etc/ssl/certs/ca.pem"]"#));
        assert!(json.contains(r#""certificate_directory_path":["/etc/ssl/certs"]"#));
    }

    #[test]
    fn test_certificate_with_inline_certs() {
        let cert = Certificate {
            certificate: vec![
                "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string(),
            ],
            ..Default::default()
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certificate_deserialization() {
        let json = r#"{"store": "chrome", "certificate_path": ["/path/to/cert.pem"]}"#;
        let cert: Certificate = serde_json::from_str(json).unwrap();
        assert_eq!(cert.store, Some(CertificateStore::Chrome));
        assert_eq!(cert.certificate_path, vec!["/path/to/cert.pem".to_string()]);
    }

    #[test]
    fn test_certificate_full_config() {
        let cert = Certificate {
            store: Some(CertificateStore::System),
            certificate: vec!["PEM_CONTENT".to_string()],
            certificate_path: vec!["/path/to/cert.pem".to_string()],
            certificate_directory_path: vec!["/path/to/certs".to_string()],
        };
        let json = serde_json::to_string_pretty(&cert).unwrap();
        assert!(json.contains("store"));
        assert!(json.contains("certificate"));
        assert!(json.contains("certificate_path"));
        assert!(json.contains("certificate_directory_path"));
    }
}

use serde::{Deserialize, Serialize};

use crate::config::util::is_false;

/// Log configuration for sing-box
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Log {
    /// Disable logging, no output after start.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,

    /// Log level. One of: `trace` `debug` `info` `warn` `error` `fatal` `panic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,

    /// Output file path. Will not write log to console after enable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,

    /// Add time to each line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<bool>,
}

/// Log level for sing-box logging
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_default_serializes_empty() {
        let log = Log::default();
        let json = serde_json::to_string(&log).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_log_level_serialization() {
        let level = LogLevel::Info;
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, r#""info""#);
    }

    #[test]
    fn test_log_with_values() {
        let log = Log {
            disabled: false,
            level: Some(LogLevel::Debug),
            output: Some("box.log".to_string()),
            timestamp: Some(true),
        };
        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains(r#""level":"debug""#));
        assert!(json.contains(r#""output":"box.log""#));
        assert!(json.contains(r#""timestamp":true"#));
        // disabled is false, should be skipped
        assert!(!json.contains("disabled"));
    }

    #[test]
    fn test_log_deserialization() {
        let json = r#"{"level": "warn", "timestamp": true}"#;
        let log: Log = serde_json::from_str(json).unwrap();
        assert_eq!(log.level, Some(LogLevel::Warn));
        assert_eq!(log.timestamp, Some(true));
        assert!(!log.disabled);
    }
}

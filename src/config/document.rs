//! Lossless, schema-backed sing-box configuration documents.
//!
//! Turntable only needs to mutate a small portion of a full sing-box
//! configuration. Keeping the template as raw JSON prevents fields outside
//! that mutation surface from being discarded by the typed Rust models.

use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::config::dns::Strategy;
use crate::config::outbound::Outbound;
use crate::config::schema::{self, SchemaBundle, SchemaValidationError};
use crate::config::semantic::{self, SemanticValidationError, SemanticWarning};

/// Errors raised while parsing or mutating a sing-box document.
#[derive(Debug, Error)]
pub enum DocumentError {
    /// The input is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A sing-box configuration must be a top-level JSON object.
    #[error("sing-box configuration must be a JSON object")]
    RootNotObject,

    /// A section has a shape that cannot be safely mutated.
    #[error("sing-box configuration field '{field}' must be {expected}")]
    InvalidSection {
        /// Field whose shape was invalid.
        field: &'static str,
        /// Expected JSON shape.
        expected: &'static str,
    },

    /// The document does not satisfy the official schema.
    #[error(transparent)]
    Schema(#[from] SchemaValidationError),
}

/// A lossless sing-box configuration backed by the official JSON Schema.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SingBoxDocument {
    root: Map<String, Value>,
}

impl SingBoxDocument {
    /// Parse JSON without applying a release-specific schema.
    ///
    /// This is used for legacy target versions whose accepted deprecated
    /// fields intentionally differ from the latest official schema.
    pub fn from_json_unchecked(json: &str) -> Result<Self, DocumentError> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_value_unchecked(value)
    }

    /// Parse and validate JSON against the bundled sing-box schema.
    pub fn from_json(json: &str) -> Result<Self, DocumentError> {
        Self::from_json_with_schema(json, schema::default_bundle())
    }

    /// Parse and validate JSON against a selected bundled sing-box schema.
    pub fn from_json_with_schema(
        json: &str,
        schema_bundle: &'static SchemaBundle,
    ) -> Result<Self, DocumentError> {
        let document = Self::from_json_unchecked(json)?;
        document.validate_schema_with(schema_bundle)?;
        Ok(document)
    }

    /// Construct a document from a JSON value without schema validation.
    pub fn from_value_unchecked(value: Value) -> Result<Self, DocumentError> {
        let Value::Object(root) = value else {
            return Err(DocumentError::RootNotObject);
        };
        Ok(Self { root })
    }

    /// Borrow the complete configuration as a JSON value.
    pub fn to_value(&self) -> Value {
        Value::Object(self.root.clone())
    }

    /// Validate the current document against the bundled official schema.
    pub fn validate_schema(&self) -> Result<(), SchemaValidationError> {
        self.validate_schema_with(schema::default_bundle())
    }

    /// Validate the current document against a selected bundled schema.
    pub fn validate_schema_with(
        &self,
        schema_bundle: &'static SchemaBundle,
    ) -> Result<(), SchemaValidationError> {
        schema_bundle.validate(&self.to_value())
    }

    /// Validate schema-annotated tag references and other semantic invariants.
    ///
    /// Call [`Self::validate_schema`] first so only matching schema branches
    /// contribute annotations.
    pub fn validate_semantics(&self) -> Result<Vec<SemanticWarning>, SemanticValidationError> {
        self.validate_semantics_with(schema::default_bundle())
    }

    /// Validate semantic invariants using a selected schema's annotations.
    pub fn validate_semantics_with(
        &self,
        schema_bundle: &'static SchemaBundle,
    ) -> Result<Vec<SemanticWarning>, SemanticValidationError> {
        semantic::validate_with_schema(&self.to_value(), schema_bundle)
    }

    /// Add the canonical schema URI when the template has not selected one.
    pub fn ensure_schema_uri(&mut self) {
        self.ensure_schema_uri_for(schema::default_bundle());
    }

    /// Add the selected schema bundle's canonical URI when none is present.
    pub fn ensure_schema_uri_for(&mut self, schema_bundle: &SchemaBundle) {
        self.root
            .entry("$schema".to_string())
            .or_insert_with(|| Value::String(schema_bundle.schema_uri().to_string()));
    }

    /// Number of configured outbounds.
    pub fn outbound_count(&self) -> Result<usize, DocumentError> {
        Ok(self.outbounds()?.len())
    }

    /// Borrow raw outbound objects without narrowing them to Turntable's typed
    /// subscription model.
    pub fn outbounds(&self) -> Result<&[Value], DocumentError> {
        match self.root.get("outbounds") {
            None => Ok(&[]),
            Some(Value::Array(outbounds)) => Ok(outbounds),
            Some(_) => Err(DocumentError::InvalidSection {
                field: "outbounds",
                expected: "an array",
            }),
        }
    }

    fn outbounds_mut(&mut self) -> Result<&mut Vec<Value>, DocumentError> {
        let value = self
            .root
            .entry("outbounds".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        value.as_array_mut().ok_or(DocumentError::InvalidSection {
            field: "outbounds",
            expected: "an array",
        })
    }

    /// Prepend generated selector tags to every template selector and URLTest
    /// outbound while preserving all other outbound fields verbatim.
    pub fn update_selectors(&mut self, new_selector_tags: &[String]) -> Result<(), DocumentError> {
        if new_selector_tags.is_empty() {
            return Ok(());
        }

        for outbound in self.outbounds_mut()? {
            let Some(object) = outbound.as_object_mut() else {
                continue;
            };
            let outbound_type = object.get("type").and_then(Value::as_str);
            if !matches!(outbound_type, Some("selector" | "urltest")) {
                continue;
            }

            let targets = object
                .entry("outbounds".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            let targets = targets
                .as_array_mut()
                .ok_or(DocumentError::InvalidSection {
                    field: "outbounds[].outbounds",
                    expected: "an array",
                })?;

            let mut updated = new_selector_tags
                .iter()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>();
            updated.append(targets);
            *targets = updated;
        }
        Ok(())
    }

    /// Append typed outbounds generated from subscriptions.
    pub fn extend_outbounds<I>(&mut self, outbounds: I) -> Result<(), DocumentError>
    where
        I: IntoIterator<Item = Outbound>,
    {
        let serialized = outbounds
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;
        self.outbounds_mut()?.extend(serialized);
        Ok(())
    }

    /// Set the global DNS strategy while retaining every other DNS field.
    pub fn set_dns_strategy(&mut self, strategy: Strategy) -> Result<(), DocumentError> {
        let dns = self
            .root
            .entry("dns".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let dns = dns.as_object_mut().ok_or(DocumentError::InvalidSection {
            field: "dns",
            expected: "an object",
        })?;
        dns.insert("strategy".to_string(), serde_json::to_value(strategy)?);
        Ok(())
    }

    /// Serialize the document as compact JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.root)
    }

    /// Serialize the document as pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.root)
    }
}

impl Serialize for SingBoxDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.root.serialize(serializer)
    }
}

impl fmt::Display for SingBoxDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_json_pretty() {
            Ok(json) => f.write_str(&json),
            Err(_) => Err(fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::config::outbound::{DirectOutbound, SelectorOutbound};
    use crate::config::schema::SCHEMA_URI;

    #[test]
    fn preserves_unmodeled_beta_2_fields_losslessly() {
        let input = json!({
            "$schema": SCHEMA_URI,
            "route": {
                "rule_set": [{
                    "type": "remote",
                    "tag": "remote",
                    "format": "source",
                    "url": "https://example.com/rules.json",
                    "initial_path": "/bootstrap"
                }]
            },
            "outbounds": [{"type": "direct", "tag": "direct"}]
        });

        let document = SingBoxDocument::from_json(&input.to_string()).unwrap();
        assert_eq!(document.to_value(), input);
    }

    #[test]
    fn updates_template_selectors_without_deserializing_other_outbounds() {
        let mut document = SingBoxDocument::from_value_unchecked(json!({
            "outbounds": [
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["direct"],
                    "interrupt_exist_connections": true
                },
                {
                    "type": "future-protocol",
                    "tag": "preserved",
                    "future_option": {"nested": true}
                }
            ]
        }))
        .unwrap();

        document
            .update_selectors(&["Provider".to_string()])
            .unwrap();

        assert_eq!(
            document.to_value()["outbounds"][0]["outbounds"],
            json!(["Provider", "direct"])
        );
        assert_eq!(
            document.to_value()["outbounds"][1]["future_option"],
            json!({"nested": true})
        );
    }

    #[test]
    fn appends_typed_generated_outbounds() {
        let mut document = SingBoxDocument::default();
        document
            .extend_outbounds([
                Outbound::Selector(SelectorOutbound::new(
                    "proxy".to_string(),
                    vec!["direct".to_string()],
                )),
                Outbound::Direct(DirectOutbound::new("direct")),
            ])
            .unwrap();
        document.ensure_schema_uri();

        assert_eq!(document.outbound_count().unwrap(), 2);
        assert_eq!(document.to_value()["outbounds"][0]["type"], "selector");
        document.validate_schema().unwrap();
    }

    #[test]
    fn sets_dns_strategy_without_dropping_unmodeled_fields() {
        let mut document = SingBoxDocument::from_value_unchecked(json!({
            "dns": {
                "servers": [],
                "future_option": {"nested": true}
            }
        }))
        .unwrap();

        document.set_dns_strategy(Strategy::Ipv4Only).unwrap();

        assert_eq!(document.to_value()["dns"]["strategy"], "ipv4_only");
        assert_eq!(
            document.to_value()["dns"]["future_option"],
            json!({"nested": true})
        );
    }
}

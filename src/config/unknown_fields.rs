//! Detection and logging of fields ignored during JSON deserialization.

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::warn;

/// Deserialize JSON and warn for every field not represented by Turntable's
/// typed configuration model.
pub fn from_json_with_warnings<T>(json: &str, source: &str) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned + Serialize,
{
    let (value, unknown_fields) = from_json(json)?;

    for path in unknown_fields {
        warn!(
            field = %path,
            source,
            "Unknown field is not implemented in Turntable and will be ignored"
        );
    }

    Ok(value)
}

/// Deserialize JSON and return the paths Serde ignored.
pub fn from_json<T>(json: &str) -> Result<(T, Vec<String>), serde_json::Error>
where
    T: DeserializeOwned + Serialize,
{
    let input: Value = serde_json::from_str(json)?;
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let mut unknown_fields = Vec::new();
    let value = serde_ignored::deserialize(&mut deserializer, |path| {
        unknown_fields.push(path.to_string());
    })?;

    let output =
        serde_json::to_value(&value).expect("serializing a deserialized value cannot fail");
    collect_missing_non_default_fields(&input, &output, "", &mut unknown_fields);
    unknown_fields.sort();
    unknown_fields.dedup();
    Ok((value, unknown_fields))
}

fn collect_missing_non_default_fields(
    input: &Value,
    output: &Value,
    path: &str,
    unknown: &mut Vec<String>,
) {
    match (input, output) {
        (Value::Object(input), Value::Object(output)) => {
            for (key, value) in input {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(output_value) = output.get(key) {
                    collect_missing_non_default_fields(value, output_value, &child_path, unknown);
                } else if !is_default_json_value(value) {
                    unknown.push(child_path);
                }
            }
        }
        (Value::Array(input), Value::Array(output)) => {
            for (index, (input, output)) in input.iter().zip(output).enumerate() {
                let child_path = if path.is_empty() {
                    index.to_string()
                } else {
                    format!("{path}.{index}")
                };
                collect_missing_non_default_fields(input, output, &child_path, unknown);
            }
        }
        _ => {}
    }
}

fn is_default_json_value(value: &Value) -> bool {
    matches!(value, Value::Null | Value::Bool(false))
        || matches!(value, Value::Number(number) if number.as_i64() == Some(0))
        || matches!(value, Value::String(value) if value.is_empty())
        || matches!(value, Value::Array(value) if value.is_empty())
        || matches!(value, Value::Object(value) if value.is_empty())
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    struct Example {
        known: bool,
    }

    #[test]
    fn parses_json_with_unknown_fields() {
        let (parsed, unknown): (Example, _) =
            super::from_json(r#"{"known":true,"not_implemented":42}"#).unwrap();
        assert!(parsed.known);
        assert_eq!(unknown, ["not_implemented"]);
    }
}

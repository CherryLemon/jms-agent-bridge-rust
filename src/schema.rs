//! The JSON-Schema subset this bridge publishes, validated before any side effect.
//!
//! Advertised schemas and hidden operation schemas are hand-written JSON, so the
//! validator only needs the keywords those schemas actually use: `type`, `required`,
//! `additionalProperties: false`, `properties`, `enum`, `const`, ranges, string
//! length, `pattern`, array bounds and `items`. `oneOf`/`anyOf` are supported for the
//! mutually exclusive execution shapes.

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct SchemaError {
    pub path: String,
    pub message: String,
}

impl SchemaError {
    fn new(path: &[String], message: impl Into<String>) -> Self {
        Self {
            path: path.join("."),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(formatter, "{}", self.message)
        } else {
            write!(formatter, "{}: {}", self.path, self.message)
        }
    }
}

pub fn validate(schema: &Value, value: &Value) -> Result<(), SchemaError> {
    let mut path = Vec::new();
    walk(schema, value, &mut path)
}

fn walk(schema: &Value, value: &Value, path: &mut Vec<String>) -> Result<(), SchemaError> {
    let Some(schema) = schema.as_object() else {
        return Ok(());
    };
    if let Some(Value::String(kind)) = schema.get("type") {
        if !type_matches(kind, value) {
            return Err(SchemaError::new(
                path,
                format!("expected {kind}, got {}", json_type(value)),
            ));
        }
    }
    if let Some(Value::Array(options)) = schema.get("enum") {
        if !options.iter().any(|option| option == value) {
            return Err(SchemaError::new(path, "value is not an allowed option"));
        }
    }
    if let Some(expected) = schema.get("const") {
        if expected != value {
            return Err(SchemaError::new(path, "value must match the fixed value"));
        }
    }
    for combinator in ["anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = schema.get(combinator) {
            let matches = branches
                .iter()
                .filter(|branch| walk(branch, value, &mut path.clone()).is_ok())
                .count();
            let ok = if combinator == "anyOf" {
                matches >= 1
            } else {
                matches == 1
            };
            if !ok {
                return Err(SchemaError::new(path, "value matches no allowed shape"));
            }
        }
    }
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(required)) = schema.get("required") {
                for key in required.iter().filter_map(Value::as_str) {
                    if !map.contains_key(key) {
                        return Err(SchemaError::new(path, format!("missing required: {key}")));
                    }
                }
            }
            let properties = schema.get("properties").and_then(Value::as_object);
            let closed = schema
                .get("additionalProperties")
                .map(|value| value == &Value::Bool(false))
                .unwrap_or(false);
            if closed {
                if let Some(properties) = properties {
                    for key in map.keys() {
                        if !properties.contains_key(key) {
                            return Err(SchemaError::new(
                                path,
                                format!("unexpected property: {key}"),
                            ));
                        }
                    }
                }
            }
            if let Some(properties) = properties {
                for (key, property_schema) in properties {
                    if let Some(item) = map.get(key) {
                        path.push(key.clone());
                        walk(property_schema, item, path)?;
                        path.pop();
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(min) = schema.get("minItems").and_then(Value::as_u64) {
                if (items.len() as u64) < min {
                    return Err(SchemaError::new(
                        path,
                        format!("needs at least {min} items"),
                    ));
                }
            }
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
                if items.len() as u64 > max {
                    return Err(SchemaError::new(
                        path,
                        format!("allows at most {max} items"),
                    ));
                }
            }
            if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                for index in 0..items.len() {
                    if items[index + 1..].contains(&items[index]) {
                        return Err(SchemaError::new(path, "items must be unique"));
                    }
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    path.push(index.to_string());
                    walk(item_schema, item, path)?;
                    path.pop();
                }
            }
        }
        Value::String(text) => {
            let length = text.chars().count() as u64;
            if let Some(min) = schema.get("minLength").and_then(Value::as_u64) {
                if length < min {
                    return Err(SchemaError::new(
                        path,
                        format!("needs at least {min} characters"),
                    ));
                }
            }
            if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
                if length > max {
                    return Err(SchemaError::new(
                        path,
                        format!("allows at most {max} characters"),
                    ));
                }
            }
            if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
                let regex = regex::Regex::new(pattern)
                    .map_err(|_| SchemaError::new(path, "invalid schema pattern"))?;
                // JSON Schema patterns are unanchored searches unless anchored.
                if !regex.is_match(text) {
                    return Err(SchemaError::new(
                        path,
                        "value does not match the required pattern",
                    ));
                }
            }
            if let Some(max) = schema.get("maxBytes").and_then(Value::as_u64) {
                if text.len() as u64 > max {
                    return Err(SchemaError::new(
                        path,
                        format!("allows at most {max} bytes"),
                    ));
                }
            }
        }
        Value::Number(number) => {
            let value = number.as_f64().unwrap_or(0.0);
            if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
                if value < min {
                    return Err(SchemaError::new(path, format!("must be >= {min}")));
                }
            }
            if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
                if value > max {
                    return Err(SchemaError::new(path, format!("must be <= {max}")));
                }
            }
            if schema.get("type").and_then(Value::as_str) == Some("integer")
                && number.as_i64().is_none()
                && number.as_u64().is_none()
            {
                return Err(SchemaError::new(path, "expected an integer"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

pub fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Remove every `title` key, matching the advertised schemas of the Python bridge.
pub fn strip_titles(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                if key == "title" {
                    continue;
                }
                out.insert(key.clone(), strip_titles(value));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(strip_titles).collect()),
        other => other.clone(),
    }
}

/// Merge a tool's `options` object into its flat argument map.
///
/// Identity, recovery and action fields stay explicit so `options` can never silently
/// retarget a request, and a field given twice is rejected instead of guessed.
pub fn merge_options(
    flat: serde_json::Map<String, Value>,
    options: Option<&Value>,
    reserved: &[&str],
) -> Result<serde_json::Map<String, Value>, String> {
    let Some(options) = options.and_then(Value::as_object) else {
        return Ok(flat);
    };
    if options.is_empty() {
        return Ok(flat);
    }
    let mut invalid: Vec<String> = options
        .keys()
        .filter(|key| reserved.contains(&key.as_str()))
        .cloned()
        .collect();
    if !invalid.is_empty() {
        invalid.sort();
        return Err(format!("options cannot override: {}", invalid.join(", ")));
    }
    let mut duplicate: Vec<String> = flat
        .keys()
        .filter(|key| options.contains_key(*key))
        .cloned()
        .collect();
    if !duplicate.is_empty() {
        duplicate.sort();
        return Err(format!("duplicate options: {}", duplicate.join(", ")));
    }
    let mut merged = flat;
    for (key, value) in options {
        merged.insert(key.clone(), value.clone());
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_missing_required_and_unknown_properties() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["target", "action"],
            "properties": {"target": {"type": "string"}, "action": {"type": "string"}},
        });
        let error = validate(&schema, &json!({"target": "a"})).unwrap_err();
        assert_eq!(error.message, "missing required: action");
        let error =
            validate(&schema, &json!({"target": "a", "action": "read", "x": 1})).unwrap_err();
        assert_eq!(error.message, "unexpected property: x");
    }

    #[test]
    fn reports_nested_array_paths() {
        let schema = json!({
            "type": "object",
            "properties": {
                "targets": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}}
            },
        });
        let error = validate(&schema, &json!({"targets": ["ok", ""]})).unwrap_err();
        assert_eq!(error.path, "targets.1");
        let error = validate(&schema, &json!({"targets": []})).unwrap_err();
        assert!(error.message.contains("at least 1 items"));
    }

    #[test]
    fn pattern_enum_and_ranges_are_enforced() {
        let schema = json!({
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "pattern": "^[A-Za-z0-9_.:-]{1,8}$"},
                "stream": {"type": "string", "enum": ["stdout", "stderr"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 16},
                "ratio": {"type": "number", "minimum": 0.5},
            },
        });
        assert!(validate(&schema, &json!({"request_id": "ok-1"})).is_ok());
        assert!(validate(&schema, &json!({"request_id": "bad id"})).is_err());
        assert!(validate(&schema, &json!({"stream": "both"})).is_err());
        assert!(validate(&schema, &json!({"limit": 17})).is_err());
        assert!(validate(&schema, &json!({"limit": 2.5})).is_err());
        assert!(validate(&schema, &json!({"ratio": 0.1})).is_err());
    }

    #[test]
    fn strip_titles_is_recursive() {
        let schema = json!({
            "title": "Root",
            "properties": {"a": {"title": "A", "type": "string"}},
            "items": [{"title": "I"}],
        });
        let stripped = strip_titles(&schema);
        assert_eq!(
            stripped,
            json!({"properties": {"a": {"type": "string"}}, "items": [{}]})
        );
    }

    #[test]
    fn options_cannot_override_identity_or_repeat_a_field() {
        let mut flat = serde_json::Map::new();
        flat.insert("target".into(), json!("a"));
        let error =
            merge_options(flat.clone(), Some(&json!({"target": "b"})), &["target"]).unwrap_err();
        assert_eq!(error, "options cannot override: target");
        let mut with_limit = flat.clone();
        with_limit.insert("limit".into(), json!(10));
        let error = merge_options(with_limit, Some(&json!({"limit": 5})), &["target"]).unwrap_err();
        assert_eq!(error, "duplicate options: limit");
        let merged = merge_options(flat, Some(&json!({"max_bytes": 256})), &["target"]).unwrap();
        assert_eq!(merged["max_bytes"], 256);
        assert_eq!(merged["target"], "a");
    }
}

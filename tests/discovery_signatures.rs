//! Operation signatures are a summary of the schemas used by the dispatcher.
use jms_bridge::schemas::{
    exact_operation_schema, full_specs, operation_discovery_etag, operation_signature, operations,
};
use serde_json::{json, Value};

fn assert_signature(name: &str, definition: &Value) {
    let schema = &definition["inputSchema"];
    let required = schema["required"].as_array();
    let line = operation_signature(name, definition);
    let rendered = line
        .strip_prefix(name)
        .and_then(|line| line.strip_prefix('('))
        .and_then(|line| line.strip_suffix(')'))
        .unwrap_or_else(|| panic!("invalid signature for {name}: {line}"));
    let rendered: Vec<&str> = if rendered.is_empty() {
        Vec::new()
    } else {
        rendered.split(", ").collect()
    };
    let properties = schema["properties"].as_object().unwrap();
    assert_eq!(rendered.len(), properties.len(), "{name}: {line}");
    let mut seen = std::collections::HashSet::new();
    let mut optional_seen = false;
    for argument in rendered {
        let name_end = argument.find(['?', '[', '=']).unwrap_or(argument.len());
        let (field, mut suffix) = argument.split_at(name_end);
        assert!(seen.insert(field), "duplicate field {field}: {line}");
        let spec = properties
            .get(field)
            .unwrap_or_else(|| panic!("unknown property {field}: {line}"));
        let mandatory = required.is_some_and(|fields| fields.iter().any(|f| f == field));
        if mandatory {
            assert!(!optional_seen, "required field after optional: {line}");
            assert!(!suffix.starts_with('?'), "{line}");
        } else {
            optional_seen = true;
            suffix = suffix
                .strip_prefix('?')
                .unwrap_or_else(|| panic!("missing optional marker: {line}"));
        }
        let expected_suffix = if let Some(fixed) = spec.get("const") {
            format!("={fixed}")
        } else if matches!(field, "limit" | "max_bytes" | "timeout" | "wait_ms") {
            match (spec.get("minimum"), spec.get("maximum")) {
                (Some(min), Some(max)) => format!("[{min}..{max}]"),
                _ => String::new(),
            }
        } else {
            String::new()
        };
        assert_eq!(suffix, expected_suffix, "{line}");
    }
}

#[test]
fn every_operation_and_filesystem_action_signature_matches_the_schema() {
    for spec in full_specs() {
        let definition = exact_operation_schema(spec.name, "").unwrap();
        assert_eq!(definition["inputSchema"], spec.input_schema);
        assert_signature(spec.name, &definition);
    }
    let operations = operations();
    for (name, definition) in operations {
        assert_signature(name, definition);
    }
    let actions = operations["jms_fs"]["inputSchema"]["properties"]["action"]["enum"]
        .as_array()
        .unwrap();
    for action in actions {
        let action = action.as_str().unwrap();
        let definition = exact_operation_schema("jms_fs", action).unwrap();
        assert_eq!(
            definition["inputSchema"]["properties"]["action"]["const"],
            action
        );
        assert_signature("jms_fs", &definition);
    }
}

#[test]
fn operation_etag_changes_when_a_schema_changes_without_a_scope_change() {
    let scope = json!(["bridge", "operations", "read", "jms_fs", "full", 0, 10]);
    let mut definition = exact_operation_schema("jms_fs", "read").unwrap();
    let first = operation_discovery_etag(&scope, &definition);
    assert_eq!(operation_discovery_etag(&scope, &definition), first);
    definition["inputSchema"]["properties"]["timeout"]["maximum"] = json!(121);
    assert_ne!(operation_discovery_etag(&scope, &definition), first);
}

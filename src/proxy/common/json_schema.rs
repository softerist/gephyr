use serde_json::Value;

const STRIP_KEYS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
];

pub fn clean_json_schema(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in STRIP_KEYS {
                map.remove(*key);
            }

            for (_, child) in map.iter_mut() {
                clean_json_schema(child);
            }
        }
        Value::Array(items) => {
            for child in items.iter_mut() {
                clean_json_schema(child);
            }
        }
        _ => {}
    }
}

pub fn fix_tool_call_args(args: &mut Value, schema: &Value) {
    if let Value::String(s) = args {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            *args = parsed;
        }
    }

    coerce_by_schema(args, schema);
}

fn schema_type(schema: &Value) -> Option<&str> {
    schema.get("type").and_then(Value::as_str)
}

fn coerce_by_schema(value: &mut Value, schema: &Value) {
    match schema_type(schema) {
        Some("boolean") => {
            if let Value::String(s) = value {
                let lowered = s.trim().to_ascii_lowercase();
                if matches!(lowered.as_str(), "true" | "1" | "yes" | "on") {
                    *value = Value::Bool(true);
                } else if matches!(lowered.as_str(), "false" | "0" | "no" | "off") {
                    *value = Value::Bool(false);
                }
            }
        }
        Some("integer") => match value {
            Value::String(s) => {
                if let Ok(i) = s.trim().parse::<i64>() {
                    *value = Value::Number(i.into());
                }
            }
            Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    *value = Value::Number((f as i64).into());
                }
            }
            _ => {}
        },
        Some("number") => {
            if let Value::String(s) = value {
                if let Ok(f) = s.trim().parse::<f64>() {
                    if let Some(n) = serde_json::Number::from_f64(f) {
                        *value = Value::Number(n);
                    }
                }
            }
        }
        Some("string") => {
            if !value.is_string() {
                *value = Value::String(value.to_string());
            }
        }
        Some("array") => {
            if !value.is_array() {
                let single = value.take();
                *value = Value::Array(vec![single]);
            }
            if let (Some(item_schema), Value::Array(items)) = (schema.get("items"), value) {
                for item in items.iter_mut() {
                    coerce_by_schema(item, item_schema);
                }
            }
        }
        Some("object") => {
            if !value.is_object() {
                *value = Value::Object(serde_json::Map::new());
            }

            if let Value::Object(obj) = value {
                if let Some(Value::Object(props)) = schema.get("properties") {
                    for (k, child_schema) in props {
                        if let Some(v) = obj.get_mut(k) {
                            coerce_by_schema(v, child_schema);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

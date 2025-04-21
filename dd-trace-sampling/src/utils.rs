// Copyright 2023-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::Value;

/// Extracts a string value from an OpenTelemetry Value
pub fn extract_string_value(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_string()),
        Value::I64(i) => Some(i.to_string()),
        Value::F64(f) => Some(f.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::Value;

    #[test]
    fn test_extract_string_value() {
        assert_eq!(
            extract_string_value(&Value::String("test".into())),
            Some("test".to_string())
        );
        assert_eq!(
            extract_string_value(&Value::I64(123)),
            Some("123".to_string())
        );
        assert_eq!(
            extract_string_value(&Value::F64(12.34)),
            Some("12.34".to_string())
        );
        assert_eq!(
            extract_string_value(&Value::Bool(true)),
            Some("true".to_string())
        );
        assert_eq!(
            extract_string_value(&Value::Bool(false)),
            Some("false".to_string())
        );
    }
}

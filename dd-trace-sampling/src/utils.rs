// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use opentelemetry::Value;

/// Extracts a string value from an OpenTelemetry Value
pub fn extract_string_value(value: &Value) -> Option<Cow<'_, str>> {
    match value {
        Value::String(s) => Some(Cow::Borrowed(s.as_str())),
        Value::I64(i) => Some(Cow::Owned(i.to_string())),
        Value::F64(f) => Some(Cow::Owned(f.to_string())),
        Value::Bool(b) => Some(Cow::Borrowed(if *b { "true" } else { "false" })),
        _ => None,
    }
}

/// Extracts a float value from an OpenTelemetry Value
pub fn extract_float_value(value: &Value) -> Option<f64> {
    match value {
        Value::F64(f) => Some(*f),
        Value::I64(i) => Some(*i as f64),
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
            extract_string_value(&Value::String("test".into())).as_deref(),
            Some("test")
        );
        assert_eq!(
            extract_string_value(&Value::I64(123)).as_deref(),
            Some("123")
        );
        assert_eq!(
            extract_string_value(&Value::F64(12.34)).as_deref(),
            Some("12.34")
        );
        assert_eq!(
            extract_string_value(&Value::Bool(true)).as_deref(),
            Some("true")
        );
        assert_eq!(
            extract_string_value(&Value::Bool(false)).as_deref(),
            Some("false")
        );
    }

    #[test]
    fn test_extract_float_value() {
        assert_eq!(extract_float_value(&Value::F64(12.34)), Some(12.34));
        assert_eq!(extract_float_value(&Value::I64(123)), Some(123.0));
        assert_eq!(extract_float_value(&Value::String("12.34".into())), None);
        assert_eq!(extract_float_value(&Value::Bool(true)), None);
    }
}

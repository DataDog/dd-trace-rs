// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

pub(crate) use datadog_opentelemetry::propagation::datadog::{
    DATADOG_PARENT_ID_KEY as PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY as SAMPLING_PRIORITY_KEY,
    DATADOG_TAGS_KEY as TAGS_KEY, DATADOG_TRACE_ID_KEY as TRACE_ID_KEY,
};

pub(crate) const CARRIER_KEY: &str = "_datadog";

pub(crate) fn validate_carrier(
    carrier: &HashMap<String, String>,
) -> Option<&HashMap<String, String>> {
    let id = carrier.get(TRACE_ID_KEY)?.parse::<u64>().ok()?;
    (id != 0).then_some(carrier)
}

pub(crate) fn carrier_from_json_object(obj: &serde_json::Value) -> Option<HashMap<String, String>> {
    let map = obj.as_object()?;
    let mut carrier = HashMap::with_capacity(map.len());
    for (k, v) in map {
        if let Some(s) = v.as_str() {
            carrier.insert(k.clone(), s.to_owned());
        }
    }
    Some(carrier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_carrier() {
        let mut carrier = HashMap::new();
        carrier.insert(TRACE_ID_KEY.to_owned(), "12345".to_owned());
        carrier.insert(PARENT_ID_KEY.to_owned(), "67890".to_owned());
        assert!(validate_carrier(&carrier).is_some());
    }

    #[test]
    fn missing_trace_id() {
        let carrier = HashMap::new();
        assert!(validate_carrier(&carrier).is_none());
    }

    #[test]
    fn zero_trace_id() {
        let mut carrier = HashMap::new();
        carrier.insert(TRACE_ID_KEY.to_owned(), "0".to_owned());
        assert!(validate_carrier(&carrier).is_none());
    }

    #[test]
    fn empty_trace_id() {
        let mut carrier = HashMap::new();
        carrier.insert(TRACE_ID_KEY.to_owned(), String::new());
        assert!(validate_carrier(&carrier).is_none());
    }

    #[test]
    fn non_numeric_trace_id() {
        let mut carrier = HashMap::new();
        carrier.insert(TRACE_ID_KEY.to_owned(), "not-a-number".to_owned());
        assert!(validate_carrier(&carrier).is_none());
    }

    #[test]
    fn carrier_from_json() {
        let json = serde_json::json!({
            "x-datadog-trace-id": "12345",
            "x-datadog-parent-id": "67890",
            "x-datadog-sampling-priority": "1"
        });
        let carrier = carrier_from_json_object(&json).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
    }

    #[test]
    fn carrier_from_non_object() {
        let json = serde_json::json!("not an object");
        assert!(carrier_from_json_object(&json).is_none());
    }
}

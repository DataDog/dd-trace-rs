// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::inference::triggers::{
    resolve_service_name, Trigger, FUNCTION_TRIGGER_EVENT_SOURCE_TAG,
};
use crate::inference::SpanData as Span;
use crate::inference::MS_TO_NS;
use serde::{de::Error, Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MSKEvent {
    pub event_source: String,
    pub event_source_arn: String,
    #[serde(rename = "records", deserialize_with = "selected_record")]
    pub record: MSKRecord,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct MSKRecord {
    pub topic: String,
    pub partition: i32,
    pub timestamp: f64,
    #[serde(default)]
    pub headers: Value,
}

/// Decodes a header value into raw bytes. Two formats have been observed:
///
/// - **Array**: elements are integers `[104, 101]` or decimal strings `["49"]`
/// - **Object** with numeric string keys and decimal string values: `{"0":"52","1":"54",...}`
fn bytes_from_header_value(val: &Value) -> Option<Vec<u8>> {
    match val {
        // Array format: elements may be integers `[104, 101]` or decimal strings `["49"]`
        Value::Array(arr) => arr
            .iter()
            .map(|v| match v {
                Value::Number(n) => n.as_u64().and_then(|n| u8::try_from(n).ok()),
                Value::String(s) => s.parse::<u8>().ok(),
                _ => None,
            })
            .collect(),
        // Object format with numeric string keys and decimal string values:
        // `{"0":"52","1":"54",...}`
        Value::Object(obj) => {
            let mut pairs: Vec<(u64, u8)> = obj
                .iter()
                .filter_map(|(k, v)| {
                    Some((k.parse::<u64>().ok()?, v.as_str()?.parse::<u8>().ok()?))
                })
                .collect();
            pairs.sort_by_key(|(idx, _)| *idx);
            Some(pairs.into_iter().map(|(_, b)| b).collect())
        }
        _ => None,
    }
}

fn values(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten().chain(
        value
            .as_object()
            .into_iter()
            .flat_map(|object| object.values()),
    )
}

fn values_mut(value: &mut Value) -> impl Iterator<Item = &mut Value> {
    let (array, object) = match value {
        Value::Array(array) => (Some(array), None),
        Value::Object(object) => (None, Some(object)),
        _ => (None, None),
    };
    array
        .into_iter()
        .flatten()
        .chain(object.into_iter().flat_map(|object| object.values_mut()))
}

fn headers_has_trace_context(headers: &Value) -> bool {
    values(headers).filter_map(Value::as_object).any(|entry| {
        entry.keys().any(|key| {
            key.eq_ignore_ascii_case("x-datadog-trace-id")
                || key.eq_ignore_ascii_case("traceparent")
        })
    })
}

fn selected_record<'de, D: Deserializer<'de>>(deserializer: D) -> Result<MSKRecord, D::Error> {
    let mut records = Value::deserialize(deserializer)?;
    let records = records
        .as_object_mut()
        .ok_or_else(|| D::Error::custom("invalid MSK records"))?;
    let selected = records
        .values_mut()
        .flat_map(values_mut)
        .find(|record| record.get("headers").is_some_and(headers_has_trace_context))
        .map(Value::take);
    let selected = selected
        .or_else(|| {
            values_mut(records.values_mut().next()?)
                .next()
                .map(Value::take)
        })
        .ok_or_else(|| D::Error::custom("missing MSK record"))?;
    serde_json::from_value(selected).map_err(D::Error::custom)
}

fn headers_to_string_map(headers: &Value) -> HashMap<String, String> {
    values(headers)
        .filter_map(Value::as_object)
        .flat_map(|entry| entry.iter())
        .filter_map(|(key, value)| {
            let bytes = bytes_from_header_value(value)?;
            Some((key.to_lowercase(), String::from_utf8(bytes).ok()?))
        })
        .collect()
}

impl Trigger for MSKEvent {
    fn new(payload: Value) -> Option<Self> {
        serde_json::from_value(payload)
            .map_err(|error| debug!("Failed to deserialize MSKEvent: {error}"))
            .ok()
    }

    fn is_match(payload: &Value) -> bool {
        let first_record_group = payload
            .get("records")
            .and_then(Value::as_object)
            .and_then(|map| map.values().next());
        let first_record = match first_record_group {
            Some(Value::Array(arr)) => arr.first(),
            Some(Value::Object(obj)) => obj.values().next(),
            _ => return false,
        };
        first_record.is_some_and(|rec| rec.get("topic").is_some())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn span_data(
        &self,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    ) -> Option<Span> {
        let mut span = Span::default();
        debug!("Enriching an Inferred Span for an MSK event");

        let cluster_name = self.event_source_arn.split('/').nth(1).unwrap_or_default();
        span.name = String::from("aws.msk");
        span.service = resolve_service_name(
            service_mapping,
            cluster_name,
            "lambda_msk",
            cluster_name,
            "msk",
            aws_service_representation_enabled,
        );
        span.r#type = String::from("web");

        span.resource.clone_from(&self.record.topic);
        span.start = (self.record.timestamp * MS_TO_NS) as i64;
        span.meta.extend([
            ("topic".to_string(), self.record.topic.clone()),
            ("partition".to_string(), self.record.partition.to_string()),
            ("event_source".to_string(), self.event_source.clone()),
            (
                "event_source_arn".to_string(),
                self.event_source_arn.clone(),
            ),
        ]);
        Some(span)
    }

    fn get_tags(&self) -> HashMap<String, String> {
        HashMap::from([(
            FUNCTION_TRIGGER_EVENT_SOURCE_TAG.to_string(),
            "msk".to_string(),
        )])
    }

    fn get_arn(&self, _region: &str, _function_name: &str) -> String {
        self.event_source_arn.clone()
    }

    fn get_carrier(&self) -> HashMap<String, String> {
        headers_to_string_map(&self.record.headers)
    }

    fn is_async(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    #[test]
    fn selects_trace_record_across_groups_in_both_formats() {
        for object_format in [false, true] {
            let mut payload: Value =
                serde_json::from_str(&read_json_file("msk_event.json")).unwrap();
            let first = serde_json::json!({"topic": "first", "partition": 0, "timestamp": 1000});
            let traced = serde_json::json!({
                "topic": "traced", "partition": 2, "timestamp": 2000,
                "headers": [{"TraceParent": [49, 50, 51]}]
            });
            payload["records"] = if object_format {
                serde_json::json!({"a": {"0": first}, "b": {"0": traced}})
            } else {
                serde_json::json!({"a": [first], "b": [traced]})
            };
            let event = MSKEvent::new(payload).unwrap();
            assert_eq!(event.record.topic, "traced");
            assert_eq!(event.record.partition, 2);
            assert_eq!(event.record.timestamp, 2000.0);
            assert_eq!(event.get_carrier()["traceparent"], "123");
        }
    }

    #[test]
    fn header_formats_preserve_decoding_and_duplicate_precedence() {
        let entries = serde_json::json!([
            {"TRACEPARENT": [49, "50", 51]},
            {"TraceParent": {"2": "54", "0": "52", "1": "53"}},
            {"invalid-utf8": [255], "invalid-byte": [256]},
            null
        ]);
        let object = Value::Object(
            entries
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value.clone()))
                .collect(),
        );
        for headers in [entries, object] {
            assert_eq!(
                headers_to_string_map(&headers),
                HashMap::from([("traceparent".into(), "456".into())])
            );
        }
    }

    #[test]
    fn test_new() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = MSKEvent::new(payload).expect("Failed to deserialize into MSKEvent");

        let record = MSKRecord {
            topic: String::from("topic1"),
            partition: 0,
            timestamp: 1_745_846_213_022f64,
            headers: Value::Array(vec![]),
        };
        let expected = MSKEvent {
            event_source: String::from("aws:kafka"),
            event_source_arn: String::from(
                "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster/751d2973-a626-431c-9d4e-d7975eb44dd7-2",
            ),
            record,
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize MSKEvent");

        assert!(MSKEvent::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize SqsRecord");
        assert!(!MSKEvent::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        let service_mapping = HashMap::new();
        let span = event.span_data(&service_mapping, true).unwrap();

        assert_eq!(span.name, "aws.msk");
        assert_eq!(span.service, "demo-cluster");
        assert_eq!(span.r#type, "web");
        assert_eq!(span.resource, "topic1");
        assert_eq!(span.start, 1_745_846_213_022_000_128);

        assert_eq!(
            span.meta,
            HashMap::from([
                ("topic".to_string(), "topic1".to_string()),
                ("partition".to_string(), "0".to_string()),
                ("event_source".to_string(), "aws:kafka".to_string()),
                (
                    "event_source_arn".to_string(),
                    "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster/751d2973-a626-431c-9d4e-d7975eb44dd7-2".to_string()
                ),
            ])
        );
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        let tags = event.get_tags();

        let expected = HashMap::from([(
            "function_trigger.event_source".to_string(),
            "msk".to_string(),
        )]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        assert_eq!(
            event.get_arn("us-east-1", ""),
            "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster/751d2973-a626-431c-9d4e-d7975eb44dd7-2"
        );
    }

    #[test]
    fn test_get_carrier() {
        let json = read_json_file("msk_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        let carrier = event.get_carrier();

        let expected = HashMap::new();

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_new_with_headers() {
        let json = read_json_file("msk_event_with_headers.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = MSKEvent::new(payload).expect("Failed to deserialize into MSKEvent");

        let record = &result.record;
        assert_eq!(record.topic, "demo-topic");
        // headers is an object with 6 entries (2 non-datadog + 4 datadog)
        assert_eq!(
            record.headers.as_object().map(serde_json::Map::len),
            Some(6)
        );
    }

    #[test]
    fn test_is_match_with_headers() {
        let json = read_json_file("msk_event_with_headers.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");

        assert!(MSKEvent::is_match(&payload));
    }

    #[test]
    fn test_new_prefers_record_with_trace_context() {
        // Two records in topic1: first has no headers, second has x-datadog-trace-id.
        // [49, 50, 51] = ASCII "123"
        let payload = serde_json::json!({
            "eventSource": "aws:kafka",
            "eventSourceArn": "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster/751d2973-a626-431c-9d4e-d7975eb44dd7-2",
            "bootstrapServers": "b-1.demo-cluster.a1bcde.c1.kafka.us-east-1.amazonaws.com:9092",
            "records": {
                "topic1": [
                    {
                        "topic": "topic1", "partition": 0, "offset": 100,
                        "timestamp": 1000.0, "timestampType": "CREATE_TIME",
                        "key": null, "value": null,
                        "headers": []
                    },
                    {
                        "topic": "topic1", "partition": 0, "offset": 101,
                        "timestamp": 2000.0, "timestampType": "CREATE_TIME",
                        "key": null, "value": null,
                        "headers": [{"x-datadog-trace-id": [49, 50, 51]}]
                    }
                ]
            }
        });

        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        let carrier = event.get_carrier();
        assert_eq!(
            carrier.get("x-datadog-trace-id").map(String::as_str),
            Some("123"),
            "Should pick the record with trace context, not the first one"
        );
    }

    #[test]
    fn test_get_carrier_with_headers() {
        let json = read_json_file("msk_event_with_headers.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = MSKEvent::new(payload).expect("Failed to deserialize MSKEvent");
        let carrier = event.get_carrier();

        // Datadog headers appear at indices 2-5; non-datadog headers at 0-1 are also decoded
        // but won't be used by the propagator.
        assert_eq!(
            carrier.get("x-datadog-trace-id").map(String::as_str),
            Some("1497116011738644768")
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").map(String::as_str),
            Some("2239801583077304042")
        );
        assert_eq!(
            carrier
                .get("x-datadog-sampling-priority")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            carrier.get("x-datadog-tags").map(String::as_str),
            Some("_dd.p.dm=-1,_dd.p.tid=699c836500000000")
        );
    }

    /// Verifies that a Java-runtime-format payload (records as object with numeric string keys)
    /// without any trace context falls back to the first record and deserializes successfully.
    #[test]
    fn test_new_java_format_no_trace_context() {
        let payload = serde_json::json!({
            "eventSource": "aws:kafka",
            "eventSourceArn": "arn:aws:kafka:us-east-1:123456789012:cluster/demo-cluster/751d2973-a626-431c-9d4e-d7975eb44dd7-2",
            "bootstrapServers": "b-1.demo-cluster.a1bcde.c1.kafka.us-east-1.amazonaws.com:9092",
            "records": {
                "demo-topic-0": {
                    "0": {
                        "topic": "demo-topic", "partition": 0, "offset": 5,
                        "timestamp": 1000.0, "timestampType": "CREATE_TIME",
                        "key": null, "value": null,
                        "headers": {}
                    },
                    "1": {
                        "topic": "demo-topic", "partition": 0, "offset": 6,
                        "timestamp": 2000.0, "timestampType": "CREATE_TIME",
                        "key": null, "value": null,
                        "headers": {}
                    }
                }
            }
        });

        let event = MSKEvent::new(payload).expect("Should deserialize despite no trace context");
        let record = &event.record;
        assert_eq!(record.topic, "demo-topic");
        assert_eq!(record.partition, 0);
        assert!(event.get_carrier().is_empty());
    }
}

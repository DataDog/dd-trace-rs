// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::eventbridge::{self, EventBridgeEvent};
use super::sns;
use super::InferredSpan;
use crate::span_inferrer::carrier::{carrier_from_json_object, CARRIER_KEY};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(crate) struct SqsEvent {
    #[serde(rename = "Records")]
    records: Vec<SqsRecord>,
}

impl SqsEvent {
    pub(crate) fn into_first_record(mut self) -> Option<SqsRecord> {
        if self.records.is_empty() {
            None
        } else {
            Some(self.records.swap_remove(0))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqsRecord {
    #[serde(rename = "eventSourceARN", default)]
    event_source_arn: String,
    #[serde(default)]
    aws_region: String,
    #[serde(default)]
    receipt_handle: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    attributes: SqsAttributes,
    #[serde(default)]
    message_attributes: HashMap<String, SqsMessageAttribute>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct SqsAttributes {
    #[serde(default)]
    sent_timestamp: String,
    #[serde(default)]
    approximate_receive_count: String,
    #[serde(default)]
    sender_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SqsMessageAttribute {
    string_value: Option<String>,
}

impl SqsRecord {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
        let queue_name = self
            .event_source_arn
            .rsplit(':')
            .next()
            .unwrap_or(&self.event_source_arn);

        let start_time_ns = self
            .attributes
            .sent_timestamp
            .parse::<i64>()
            .ok()
            .map(|ms| ms * 1_000_000);

        let mut tags = HashMap::new();
        tags.insert("source_arn".to_owned(), self.event_source_arn.clone());
        tags.insert("aws_region".to_owned(), self.aws_region.clone());
        let retry_count = if self.attributes.approximate_receive_count.is_empty() {
            "1"
        } else {
            &self.attributes.approximate_receive_count
        };
        tags.insert("retry_count".to_owned(), retry_count.to_owned());
        if !self.receipt_handle.is_empty() {
            tags.insert("receipt_handle".to_owned(), self.receipt_handle.clone());
        }
        if !self.attributes.sender_id.is_empty() {
            tags.insert("sender_id".to_owned(), self.attributes.sender_id.clone());
        }

        let sqs_span = InferredSpan {
            operation: "aws.sqs",
            trigger_source: "sqs",
            trigger_arn: Some(self.event_source_arn.clone()),
            service: queue_name.to_owned(),
            resource: queue_name.to_owned(),
            span_type: "web",
            start_time_ns,
            is_async: true,
            tags,
        };

        if let Ok(inner) = serde_json::from_str::<Value>(&self.body) {
            if sns::is_match_inner(&inner) {
                if let Some((nested_carrier, mut nested_spans)) = sns::extract_inner(&inner) {
                    nested_spans.push(sqs_span);
                    return Some((nested_carrier, nested_spans));
                }
            }
            if eventbridge::is_match(&inner) {
                if let Ok(eb) = serde_json::from_value::<EventBridgeEvent>(inner) {
                    if let Some((eb_carrier, mut eb_spans)) = eb.extract() {
                        eb_spans.push(sqs_span);
                        return Some((eb_carrier, eb_spans));
                    }
                }
            }
        }

        let carrier = self.extract_carrier()?;
        Some((carrier, vec![sqs_span]))
    }

    fn extract_carrier(&self) -> Option<HashMap<String, String>> {
        let dd_attr = self.message_attributes.get(CARRIER_KEY)?;
        let value = dd_attr.string_value.as_deref()?;
        let json: Value = serde_json::from_str(value).ok()?;
        carrier_from_json_object(&json)
    }
}

/// Match SQS events: `Records[0].eventSource == "aws:sqs"`.
pub(crate) fn is_match(payload: &Value) -> bool {
    payload
        .get("Records")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("eventSource"))
        .and_then(|s| s.as_str())
        == Some("aws:sqs")
}

#[cfg(test)]
fn extract(payload: &Value) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
    let event: SqsEvent = serde_json::from_value(payload.clone()).ok()?;
    event.into_first_record()?.extract()
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_sqs_event() {
        let event = load_payload("sqs_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_non_sqs() {
        let event = json!({ "Records": [{ "Sns": {} }] });
        assert!(!is_match(&event));
    }

    #[test]
    fn extract_carrier_and_span() {
        let event = load_payload("sqs_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "12345");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].operation, "aws.sqs");
        assert_eq!(spans[0].service, "my-queue");
        assert_eq!(
            spans[0].tags.get("source_arn").unwrap(),
            "arn:aws:sqs:us-east-1:123456789:my-queue"
        );
        assert_eq!(spans[0].tags.get("retry_count").unwrap(), "1");
        assert_eq!(spans[0].start_time_ns, Some(1718444400000 * 1_000_000));
    }

    #[test]
    fn extract_without_carrier() {
        let event = load_payload("sqs_event_no_carrier.json");
        assert!(extract(&event).is_none());
    }

    #[test]
    fn nested_sns_in_sqs() {
        let event = load_payload("sns_sqs_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "55555");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].operation, "aws.sns");
        assert_eq!(spans[1].operation, "aws.sqs");
    }

    #[test]
    fn nested_eventbridge_in_sqs() {
        let event = load_payload("eventbridge_sqs_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "77777");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].operation, "aws.eventbridge");
        assert_eq!(spans[1].operation, "aws.sqs");
    }
}

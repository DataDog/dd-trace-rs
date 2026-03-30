// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::eventbridge::{self, EventBridgeEvent};
use super::sns;
use super::InferredSpan;
use crate::span_inferrer::carrier::{carrier_from_json_object, DATADOG_ATTRIBUTE_KEY};

const SOURCE_ARN: &str = "source_arn";
const AWS_REGION: &str = "aws_region";
const RETRY_COUNT: &str = "retry_count";
const RECEIPT_HANDLE: &str = "receipt_handle";
const SENDER_ID: &str = "sender_id";
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
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, InferredSpan)> {
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
        tags.insert(SOURCE_ARN.to_owned(), self.event_source_arn.clone());
        tags.insert(AWS_REGION.to_owned(), self.aws_region.clone());
        tags.insert(
            RETRY_COUNT.to_owned(),
            self.attributes.approximate_receive_count.clone(),
        );
        if !self.receipt_handle.is_empty() {
            tags.insert(RECEIPT_HANDLE.to_owned(), self.receipt_handle.clone());
        }
        if !self.attributes.sender_id.is_empty() {
            tags.insert(SENDER_ID.to_owned(), self.attributes.sender_id.clone());
        }

        let mut sqs_span = InferredSpan {
            operation: "aws.sqs",
            trigger_source: "sqs",
            trigger_arn: Some(self.event_source_arn.clone()),
            service: queue_name.to_owned(),
            resource: queue_name.to_owned(),
            span_type: "web",
            start_time_ns,
            is_async: true,
            tags,
            wrapped_by: None,
        };

        if let Ok(inner) = serde_json::from_str::<Value>(&self.body) {
            if sns::is_match_inner(&inner) {
                if let Some((nested_carrier, sns_span)) = sns::extract_inner(&inner) {
                    sqs_span.wrapped_by = Some(Box::new(sns_span));
                    return Some((nested_carrier, sqs_span));
                }
            }
            if eventbridge::is_match(&inner) {
                if let Ok(eb) = serde_json::from_value::<EventBridgeEvent>(inner) {
                    if let Some((eb_carrier, eb_span)) = eb.extract() {
                        sqs_span.wrapped_by = Some(Box::new(eb_span));
                        return Some((eb_carrier, sqs_span));
                    }
                }
            }
        }

        let carrier = self.extract_carrier().unwrap_or_default();
        Some((carrier, sqs_span))
    }

    fn extract_carrier(&self) -> Option<HashMap<String, String>> {
        let dd_attr = self.message_attributes.get(DATADOG_ATTRIBUTE_KEY)?;
        let value = dd_attr.string_value.as_deref()?;
        let json: Value = serde_json::from_str(value).ok()?;
        carrier_from_json_object(&json)
    }
}

pub(crate) fn is_match(payload: &Value) -> bool {
    payload
        .get("Records")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("eventSource"))
        .and_then(|s| s.as_str())
        == Some("aws:sqs")
}

#[cfg(test)]
fn extract(payload: &Value) -> Option<(HashMap<String, String>, InferredSpan)> {
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
    fn extracts_carrier_and_inferred_span() {
        let event = load_payload("sqs_event.json");

        let (carrier, span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "2684756524522091840"
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "7431398482019833808"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
        assert_eq!(span.operation, "aws.sqs");
        assert_eq!(span.service, "MyQueue");
        assert_eq!(span.resource, "MyQueue");
        assert_eq!(span.span_type, "web");
        assert_eq!(
            span.tags.get("receipt_handle").unwrap(),
            "MessageReceiptHandle"
        );
        assert_eq!(span.tags.get("retry_count").unwrap(), "1");
        assert_eq!(span.tags.get("sender_id").unwrap(), "123456789012");
        assert_eq!(
            span.tags.get("source_arn").unwrap(),
            "arn:aws:sqs:us-east-1:123456789012:MyQueue"
        );
        assert_eq!(span.tags.get("aws_region").unwrap(), "us-east-1");
        assert_eq!(span.start_time_ns, Some(1523232000000 * 1_000_000));
    }

    #[test]
    fn get_carrier_from_sns() {
        let event = load_payload("sns_sqs_event.json");

        let (carrier, span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "2776434475358637757"
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "4493917105238181843"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
        assert_eq!(span.operation, "aws.sqs");
        assert_eq!(span.wrapped_by.as_ref().unwrap().operation, "aws.sns");
    }

    #[test]
    fn get_carrier_from_sns_binary() {
        let event = load_payload("sns_sqs_binary_event.json");

        let (carrier, _span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "5863834085596065348"
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "2752725546543693249"
        );
        assert_eq!(
            carrier.get("tracestate").unwrap(),
            "dd=s:1;p:2633a54ccde13dc1;t.tid:6801584a00000000;t.dm:-1"
        );
        assert_eq!(
            carrier.get("traceparent").unwrap(),
            "00-6801584a00000000516086086dc7ee44-2633a54ccde13dc1-01"
        );
        assert_eq!(
            carrier.get("x-datadog-tags").unwrap(),
            "_dd.p.dm=-1,_dd.p.tid=6801584a00000000"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
    }

    #[test]
    fn get_carrier_from_eventbridge() {
        let event = load_payload("eventbridge_sqs_event.json");

        let (carrier, span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "7379586022458917877"
        );
        assert_eq!(
            carrier.get("traceparent").unwrap(),
            "00-000000000000000066698e63821a03f5-24b17e9b6476c018-01"
        );
        assert_eq!(carrier.get("x-datadog-tags").unwrap(), "_dd.p.dm=-0");
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "2644033662113726488"
        );
        assert_eq!(carrier.get("tracestate").unwrap(), "dd=t.dm:-0;s:1");
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
        assert_eq!(span.operation, "aws.sqs");
        assert_eq!(
            span.wrapped_by.as_ref().unwrap().operation,
            "aws.eventbridge"
        );
    }
}

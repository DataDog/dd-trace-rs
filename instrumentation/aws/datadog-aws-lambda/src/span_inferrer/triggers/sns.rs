// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::eventbridge::{self, EventBridgeEvent};
use super::InferredSpan;
use crate::span_inferrer::carrier::{carrier_from_json_object, DATADOG_ATTRIBUTE_KEY};

const TOPIC_ARN: &str = "topic_arn";
const TOPIC_NAME: &str = "topicname";
const MESSAGE_ID: &str = "message_id";
const SNS_TYPE: &str = "type";
const SUBJECT: &str = "subject";
const EVENT_SUBSCRIPTION_ARN: &str = "event_subscription_arn";
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(crate) struct SnsEvent {
    #[serde(rename = "Records")]
    records: Vec<SnsRecord>,
}

impl SnsEvent {
    pub(crate) fn into_first_record(mut self) -> Option<SnsRecord> {
        if self.records.is_empty() {
            None
        } else {
            Some(self.records.swap_remove(0))
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct SnsRecord {
    #[serde(rename = "Sns")]
    sns: SnsEntity,
    #[serde(rename = "EventSubscriptionArn", default)]
    event_subscription_arn: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SnsEntity {
    topic_arn: String,
    message_id: String,
    #[serde(rename = "Type")]
    sns_type: String,
    subject: Option<String>,
    timestamp: String,
    message: String,
    message_attributes: HashMap<String, SnsMessageAttribute>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SnsMessageAttribute {
    #[serde(rename = "Type")]
    attr_type: String,
    value: String,
}

impl SnsRecord {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, InferredSpan)> {
        let (carrier, mut span) = self.sns.extract_spans()?;
        if let Some(ref arn) = self.event_subscription_arn {
            span.tags
                .insert(EVENT_SUBSCRIPTION_ARN.to_owned(), arn.clone());
        }
        Some((carrier, span))
    }
}

impl SnsEntity {
    fn extract_spans(&self) -> Option<(HashMap<String, String>, InferredSpan)> {
        let carrier = self.extract_carrier().unwrap_or_default();

        let topic_name = self.topic_arn.rsplit(':').next().unwrap_or(&self.topic_arn);
        let subject = self.subject.as_deref().unwrap_or("");

        let start_time_ns = eventbridge::parse_iso_time(&self.timestamp);

        let mut tags = HashMap::new();
        tags.insert(TOPIC_ARN.to_owned(), self.topic_arn.clone());
        tags.insert(TOPIC_NAME.to_owned(), topic_name.to_owned());
        tags.insert(MESSAGE_ID.to_owned(), self.message_id.clone());
        tags.insert(SNS_TYPE.to_owned(), self.sns_type.clone());
        if !subject.is_empty() {
            tags.insert(SUBJECT.to_owned(), subject.to_owned());
        }

        let mut sns_span = InferredSpan {
            operation: "aws.sns",
            trigger_source: "sns",
            trigger_arn: Some(self.topic_arn.clone()),
            service: topic_name.to_owned(),
            resource: topic_name.to_owned(),
            span_type: "web",
            start_time_ns,
            is_async: true,
            tags,
            wrapped_by: None,
        };

        if let Ok(inner) = serde_json::from_str::<Value>(&self.message) {
            if eventbridge::is_match(&inner) {
                if let Ok(eb) = serde_json::from_value::<EventBridgeEvent>(inner) {
                    if let Some((eb_carrier, eb_span)) = eb.extract() {
                        sns_span.wrapped_by = Some(Box::new(eb_span));
                        return Some((eb_carrier, sns_span));
                    }
                }
            }
        }

        Some((carrier, sns_span))
    }

    fn extract_carrier(&self) -> Option<HashMap<String, String>> {
        let dd_attr = self.message_attributes.get(DATADOG_ATTRIBUTE_KEY)?;
        if dd_attr.attr_type == "Binary" {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &dd_attr.value)
                    .ok()?;
            let json: Value = serde_json::from_slice(&decoded).ok()?;
            carrier_from_json_object(&json)
        } else {
            let json: Value = serde_json::from_str(&dd_attr.value).ok()?;
            carrier_from_json_object(&json)
        }
    }
}

pub(crate) fn is_match(payload: &Value) -> bool {
    payload
        .get("Records")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("Sns"))
        .is_some()
}

/// Match an inner SNS notification object (not wrapped in Lambda `Records`).
/// Used by SQS to detect SNS-in-SQS: the SQS body contains the raw SNS
/// notification with `Type == "Notification"` and a `TopicArn`.
pub(crate) fn is_match_inner(payload: &Value) -> bool {
    payload.get("Type").and_then(|v| v.as_str()) == Some("Notification")
        && payload.get("TopicArn").is_some()
}

/// Extract carrier and inferred span(s) from a raw SNS notification object.
/// Called by SQS for nested SNS-in-SQS detection.
pub(crate) fn extract_inner(payload: &Value) -> Option<(HashMap<String, String>, InferredSpan)> {
    let entity: SnsEntity = serde_json::from_value(payload.clone()).ok()?;
    entity.extract_spans()
}

#[cfg(test)]
fn extract(payload: &Value) -> Option<(HashMap<String, String>, InferredSpan)> {
    let event: SnsEvent = serde_json::from_value(payload.clone()).ok()?;
    event.into_first_record()?.extract()
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::load_payload;
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_sns_event() {
        let event = load_payload("sns_event.json");
        assert!(is_match(&event));
    }

    #[test]
    fn rejects_non_sns() {
        let event = json!({ "Records": [{ "eventSource": "aws:sqs" }] });
        assert!(!is_match(&event));
    }

    #[test]
    fn enrich_span() {
        let event = load_payload("sns_event.json");

        let (carrier, span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "4948377316357291421"
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "6746998015037429512"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
        assert_eq!(span.operation, "aws.sns");
        assert_eq!(span.service, "serverlessTracingTopicPy");
        assert_eq!(span.resource, "serverlessTracingTopicPy");
        assert_eq!(span.span_type, "web");
        assert_eq!(
            span.tags.get("topicname").unwrap(),
            "serverlessTracingTopicPy"
        );
        assert_eq!(
            span.tags.get("topic_arn").unwrap(),
            "arn:aws:sns:sa-east-1:425362996713:serverlessTracingTopicPy"
        );
        assert_eq!(
            span.tags.get("message_id").unwrap(),
            "87056a47-f506-5d77-908b-303605d3b197"
        );
        assert_eq!(span.tags.get("type").unwrap(), "Notification");
        assert_eq!(
            span.tags.get("event_subscription_arn").unwrap(),
            "arn:aws:sns:sa-east-1:425362996713:serverlessTracingTopicPy:224b60ba-befc-4830-ad96-f1f0ac94eb04"
        );
        // subject is null in this fixture — no subject tag
        assert!(!span.tags.contains_key("subject"));
    }

    #[test]
    fn get_carrier_from_binary_value() {
        let event = load_payload("sns_event_binary.json");

        let (carrier, _span) = extract(&event).unwrap();
        assert_eq!(
            carrier.get("x-datadog-trace-id").unwrap(),
            "4948377316357291421"
        );
        assert_eq!(
            carrier.get("x-datadog-parent-id").unwrap(),
            "6746998015037429512"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
    }

    #[test]
    fn get_carrier_from_event_bridge() {
        let event = load_payload("eventbridge_sns_event.json");

        let (carrier, span) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-resource-name").unwrap(), "test-bus");
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "12345");
        assert_eq!(
            carrier.get("x-datadog-start-time").unwrap(),
            "1726515840997"
        );
        assert_eq!(carrier.get("x-datadog-sampling-priority").unwrap(), "1");
        assert_eq!(carrier.get("x-datadog-parent-id").unwrap(), "67890");
        assert_eq!(
            carrier.get("x-datadog-tags").unwrap(),
            "_dd.p.dm=-1,_dd.p.tid=123567890"
        );
        assert_eq!(span.operation, "aws.sns");
        assert_eq!(
            span.wrapped_by.as_ref().unwrap().operation,
            "aws.eventbridge"
        );
    }
}

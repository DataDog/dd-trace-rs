// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::eventbridge::{self, EventBridgeEvent};
use super::InferredSpan;
use crate::span_inferrer::carrier::{carrier_from_json_object, CARRIER_KEY};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
pub(crate) struct SnsEvent {
    #[serde(rename = "Records")]
    records: Vec<SnsRecord>,
}

impl SnsEvent {
    pub(crate) fn into_first_entity(mut self) -> Option<SnsEntity> {
        if self.records.is_empty() {
            None
        } else {
            Some(self.records.swap_remove(0).sns)
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct SnsRecord {
    #[serde(rename = "Sns")]
    sns: SnsEntity,
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

impl SnsEntity {
    pub(crate) fn extract(&self) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
        let carrier = self.extract_carrier()?;

        let topic_name = self.topic_arn.rsplit(':').next().unwrap_or(&self.topic_arn);
        let subject = self.subject.as_deref().unwrap_or("");

        let start_time_ns = eventbridge::parse_iso_time(&self.timestamp);

        let mut tags = HashMap::new();
        tags.insert("topic_arn".to_owned(), self.topic_arn.clone());
        tags.insert("message_id".to_owned(), self.message_id.clone());
        tags.insert("type".to_owned(), self.sns_type.clone());
        if !subject.is_empty() {
            tags.insert("subject".to_owned(), subject.to_owned());
        }

        let sns_span = InferredSpan {
            operation: "aws.sns",
            trigger_source: "sns",
            trigger_arn: Some(self.topic_arn.clone()),
            service: topic_name.to_owned(),
            resource: topic_name.to_owned(),
            span_type: "web",
            start_time_ns,
            is_async: true,
            tags,
        };

        if let Ok(inner) = serde_json::from_str::<Value>(&self.message) {
            if eventbridge::is_match(&inner) {
                if let Ok(eb) = serde_json::from_value::<EventBridgeEvent>(inner) {
                    if let Some((eb_carrier, mut eb_spans)) = eb.extract() {
                        eb_spans.push(sns_span);
                        return Some((eb_carrier, eb_spans));
                    }
                }
            }
        }

        Some((carrier, vec![sns_span]))
    }

    fn extract_carrier(&self) -> Option<HashMap<String, String>> {
        let dd_attr = self.message_attributes.get(CARRIER_KEY)?;
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

/// Match SNS events: `Records[0].Sns` exists.
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
pub(crate) fn extract_inner(
    payload: &Value,
) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
    let entity: SnsEntity = serde_json::from_value(payload.clone()).ok()?;
    entity.extract()
}

#[cfg(test)]
fn extract(payload: &Value) -> Option<(HashMap<String, String>, Vec<InferredSpan>)> {
    let event: SnsEvent = serde_json::from_value(payload.clone()).ok()?;
    event.into_first_entity()?.extract()
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
    fn extract_string_carrier() {
        let event = load_payload("sns_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "12345");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].operation, "aws.sns");
        assert_eq!(spans[0].service, "my-topic");
        assert_eq!(spans[0].tags.get("message_id").unwrap(), "msg-001");
        assert_eq!(spans[0].tags.get("subject").unwrap(), "Test Subject");
    }

    #[test]
    fn extract_binary_carrier() {
        use base64::Engine;

        let carrier_json = json!({
            "x-datadog-trace-id": "99999",
            "x-datadog-parent-id": "88888",
            "x-datadog-sampling-priority": "1"
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&carrier_json).unwrap());

        // Binary carrier can't easily be expressed in a static JSON file,
        // so we build this one inline.
        let event = json!({
            "Records": [{
                "Sns": {
                    "TopicArn": "arn:aws:sns:us-east-1:123456789:my-topic",
                    "MessageId": "msg-001",
                    "Type": "Notification",
                    "Subject": "Test Subject",
                    "Timestamp": "2024-06-15T10:30:00Z",
                    "Message": "hello world",
                    "MessageAttributes": {
                        "_datadog": {
                            "Type": "Binary",
                            "Value": encoded
                        }
                    }
                }
            }]
        });

        let (carrier, spans) = extract(&event).unwrap();
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "99999");
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn extract_without_carrier() {
        let event = load_payload("sns_event_no_carrier.json");
        assert!(extract(&event).is_none());
    }

    #[test]
    fn nested_eventbridge_in_sns() {
        let event = load_payload("eventbridge_sns_event.json");

        let (carrier, spans) = extract(&event).unwrap();
        // Uses the inner EventBridge carrier
        assert_eq!(carrier.get("x-datadog-trace-id").unwrap(), "55555");
        // EventBridge span first, then SNS
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].operation, "aws.eventbridge");
        assert_eq!(spans[1].operation, "aws.sns");
    }
}

// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::inference::SpanData as Span;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use crate::inference::{
    triggers::{ServiceNameResolver, Trigger, FUNCTION_TRIGGER_EVENT_SOURCE_TAG},
    S_TO_NS,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DynamoDbRecord {
    #[serde(rename = "dynamodb")]
    pub dynamodb: DynamoDbEntity,
    #[serde(rename = "eventID")]
    pub event_id: String,
    #[serde(rename = "eventName")]
    pub event_name: String,
    #[serde(rename = "eventVersion")]
    pub event_version: String,
    #[serde(rename = "eventSourceARN")]
    pub event_source_arn: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DynamoDbEntity {
    #[serde(rename = "ApproximateCreationDateTime")]
    pub approximate_creation_date_time: f64,
    #[serde(rename = "SizeBytes")]
    pub size_bytes: i64,
    #[serde(rename = "StreamViewType")]
    pub stream_view_type: String,
    #[serde(rename = "Keys")]
    pub keys: HashMap<String, AttributeValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// An attribute value is formatted like this: {"S": "string_value"}
// and it can be a string, number (as a string), or binary value (as a Base64-encoded string).
pub enum AttributeValue {
    S(String),
    N(String),
    B(String),
}

impl Trigger for DynamoDbRecord {
    fn new(payload: Value) -> Option<Self>
    where
        Self: Sized,
    {
        let records = payload.get("Records").and_then(Value::as_array);
        match records {
            Some(records) => {
                match serde_json::from_value::<DynamoDbRecord>(records.first()?.clone()) {
                    Ok(event) => Some(event),
                    Err(e) => {
                        debug!("Failed to deserialize DynamoDB Record: {e}");
                        None
                    }
                }
            }
            None => None,
        }
    }

    fn is_match(payload: &Value) -> bool
    where
        Self: Sized,
    {
        if let Some(first_record) = payload
            .get("Records")
            .and_then(Value::as_array)
            .and_then(|r| r.first())
        {
            first_record.get("dynamodb").is_some()
        } else {
            false
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn enrich_span(
        &self,
        span: &mut Span,
        service_mapping: &HashMap<String, String>,
        aws_service_representation_enabled: bool,
    ) {
        debug!("Enriching an Inferred Span for a DynamoDB event");
        let table_name = self.get_specific_identifier();
        let resource = format!("{} {}", self.event_name.clone(), table_name);

        let start_time = (self.dynamodb.approximate_creation_date_time * S_TO_NS) as i64;

        let service_name = self.resolve_service_name(
            service_mapping,
            &table_name,
            "dynamodb",
            aws_service_representation_enabled,
        );

        span.name = String::from("aws.dynamodb");
        span.service.clone_from(&service_name);
        span.resource = resource;
        span.r#type = String::from("web");
        span.start = start_time;
        span.meta.extend(HashMap::from([
            ("operation_name".to_string(), String::from("aws.dynamodb")),
            ("event_id".to_string(), self.event_id.clone()),
            ("event_name".to_string(), self.event_name.clone()),
            ("event_version".to_string(), self.event_version.clone()),
            (
                "event_source_arn".to_string(),
                self.event_source_arn.clone(),
            ),
            (
                "size_bytes".to_string(),
                self.dynamodb.size_bytes.to_string(),
            ),
            (
                "stream_view_type".to_string(),
                self.dynamodb.stream_view_type.clone(),
            ),
            ("table_name".to_string(), table_name.clone()),
        ]));
    }

    fn get_tags(&self) -> HashMap<String, String> {
        HashMap::from([(
            FUNCTION_TRIGGER_EVENT_SOURCE_TAG.to_string(),
            "dynamodb".to_string(),
        )])
    }

    fn get_arn(&self, _region: &str) -> String {
        self.event_source_arn.clone()
    }

    fn get_carrier(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn is_async(&self) -> bool {
        true
    }
}

impl ServiceNameResolver for DynamoDbRecord {
    fn get_specific_identifier(&self) -> String {
        self.event_source_arn
            .split('/')
            .nth(1)
            .unwrap_or_default()
            .to_string()
    }

    fn get_generic_identifier(&self) -> &'static str {
        "lambda_dynamodb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    #[test]
    fn test_new() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = DynamoDbRecord::new(payload).expect("Failed to deserialize into Record");

        let mut expected_keys = HashMap::new();
        expected_keys.insert("Id".to_string(), AttributeValue::N("101".to_string()));

        let expected = DynamoDbRecord {
            dynamodb: DynamoDbEntity {
                approximate_creation_date_time: 1_428_537_600.0,
                size_bytes: 26,
                stream_view_type: String::from("NEW_AND_OLD_IMAGES"),
                keys: expected_keys,
            },
            event_id: String::from("c4ca4238a0b923820dcc509a6f75849b"),
            event_name: String::from("INSERT"),
            event_version: String::from("1.1"),
            event_source_arn: String::from(
                "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899",
            ),
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize DynamoDbRecord");

        assert!(DynamoDbRecord::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize SqsRecord");
        assert!(!DynamoDbRecord::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");
        let mut span = Span::default();
        let service_mapping = HashMap::new();
        event.enrich_span(&mut span, &service_mapping, true);
        assert_eq!(span.name, "aws.dynamodb");
        assert_eq!(span.service, "ExampleTableWithStream");
        assert_eq!(span.resource, "INSERT ExampleTableWithStream");
        assert_eq!(span.r#type, "web");

        assert_eq!(
            span.meta,
            HashMap::from([
                ("operation_name".to_string(), "aws.dynamodb".to_string()),
                ("event_id".to_string(), "c4ca4238a0b923820dcc509a6f75849b".to_string()),
                ("event_name".to_string(), "INSERT".to_string()),
                ("event_version".to_string(), "1.1".to_string()),
                (
                    "event_source_arn".to_string(),
                    "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899".to_string()
                ),
                ("size_bytes".to_string(), "26".to_string()),
                ("stream_view_type".to_string(), "NEW_AND_OLD_IMAGES".to_string()),
                ("table_name".to_string(), "ExampleTableWithStream".to_string()),
            ])
        );
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");
        let tags = event.get_tags();

        let expected = HashMap::from([(
            "function_trigger.event_source".to_string(),
            "dynamodb".to_string(),
        )]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");
        assert_eq!(
            event.get_arn("us-east-1"),
            "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899"
        );
    }

    #[test]
    fn test_get_carrier() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::new();

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_resolve_service_name_with_representation_enabled() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");

        // Test 1: Specific mapping takes priority
        let specific_service_mapping = HashMap::from([
            (
                "ExampleTableWithStream".to_string(),
                "specific-service".to_string(),
            ),
            ("lambda_dynamodb".to_string(), "generic-service".to_string()),
        ]);

        assert_eq!(
            event.resolve_service_name(
                &specific_service_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                true // aws_service_representation_enabled
            ),
            "specific-service"
        );

        // Test 2: Generic mapping is used when specific not found
        let generic_service_mapping =
            HashMap::from([("lambda_dynamodb".to_string(), "generic-service".to_string())]);
        assert_eq!(
            event.resolve_service_name(
                &generic_service_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                true // aws_service_representation_enabled
            ),
            "generic-service"
        );

        // Test 3: When no mapping exists, uses instance name (table name)
        let empty_mapping = HashMap::new();
        assert_eq!(
            event.resolve_service_name(
                &empty_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                true // aws_service_representation_enabled
            ),
            event.get_specific_identifier() // instance name
        );
    }

    #[test]
    fn test_resolve_service_name_with_representation_disabled() {
        let json = read_json_file("dynamodb_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = DynamoDbRecord::new(payload).expect("Failed to deserialize DynamoDbRecord");

        // Test 1: With specific mapping - still respects mapping
        let specific_service_mapping = HashMap::from([
            (
                "ExampleTableWithStream".to_string(),
                "specific-service".to_string(),
            ),
            ("lambda_dynamodb".to_string(), "generic-service".to_string()),
        ]);

        assert_eq!(
            event.resolve_service_name(
                &specific_service_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                false // aws_service_representation_enabled = false
            ),
            "specific-service"
        );

        // Test 2: With generic mapping - still respects mapping
        let generic_service_mapping =
            HashMap::from([("lambda_dynamodb".to_string(), "generic-service".to_string())]);
        assert_eq!(
            event.resolve_service_name(
                &generic_service_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                false // aws_service_representation_enabled = false
            ),
            "generic-service"
        );

        // Test 3: When no mapping exists, uses fallback value
        let empty_mapping = HashMap::new();
        assert_eq!(
            event.resolve_service_name(
                &empty_mapping,
                &event.get_specific_identifier(),
                "dynamodb",
                false // aws_service_representation_enabled = false
            ),
            "dynamodb" // fallback value
        );
    }
}

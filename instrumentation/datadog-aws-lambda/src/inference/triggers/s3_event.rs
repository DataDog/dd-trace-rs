// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::inference::SpanData as Span;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

use crate::inference::{
    triggers::{ServiceNameResolver, Trigger, FUNCTION_TRIGGER_EVENT_SOURCE_TAG},
    MS_TO_NS,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct S3Record {
    #[serde(rename = "eventSource")]
    pub event_source: String,
    #[serde(rename = "eventTime")]
    pub event_time: DateTime<Utc>,
    #[serde(rename = "eventName")]
    pub event_name: String,
    pub s3: S3Entity,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct S3Entity {
    pub bucket: S3Bucket,
    pub object: S3Object,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct S3Bucket {
    pub name: String,
    pub arn: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct S3Object {
    pub key: String,
    pub size: Option<i64>,
    #[serde(rename = "eTag")]
    pub e_tag: Option<String>,
}

impl Trigger for S3Record {
    fn new(mut payload: serde_json::Value) -> Option<Self> {
        match serde_json::from_value::<S3Record>(super::take_first_record(&mut payload)?) {
            Ok(record) => Some(record),
            Err(e) => {
                debug!("Failed to deserialize S3 Record: {e}");
                None
            }
        }
    }

    fn is_match(payload: &serde_json::Value) -> bool {
        if let Some(first_record) = payload
            .get("Records")
            .and_then(Value::as_array)
            .and_then(|r| r.first())
        {
            first_record.get("s3").is_some()
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
        debug!("Enriching an InferredSpan span with S3 event");
        let bucket_name = self.get_specific_identifier();
        let start_time = self
            .event_time
            .timestamp_nanos_opt()
            .unwrap_or((self.event_time.timestamp_millis() as f64 * MS_TO_NS) as i64);

        let service_name = self.resolve_service_name(
            service_mapping,
            &bucket_name,
            "s3",
            aws_service_representation_enabled,
        );

        span.name = String::from("aws.s3");
        span.service = service_name;
        span.resource.clone_from(&bucket_name);
        span.r#type = String::from("web");
        span.start = start_time;
        span.meta.extend(HashMap::from([
            ("operation_name".to_string(), String::from("aws.s3")),
            ("event_name".to_string(), self.event_name.clone()),
            ("bucketname".to_string(), bucket_name),
            ("bucket_arn".to_string(), self.s3.bucket.arn.clone()),
            ("object_key".to_string(), self.s3.object.key.clone()),
        ]));
        if let Some(size) = self.s3.object.size {
            span.meta.insert("object_size".into(), size.to_string());
        }
        if let Some(etag) = &self.s3.object.e_tag {
            span.meta.insert("object_etag".into(), etag.clone());
        }
    }

    fn get_tags(&self) -> HashMap<String, String> {
        HashMap::from([(
            FUNCTION_TRIGGER_EVENT_SOURCE_TAG.to_string(),
            "s3".to_string(),
        )])
    }

    fn get_arn(&self, _region: &str, _function_name: &str) -> String {
        self.s3.bucket.arn.clone()
    }

    fn get_carrier(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    fn is_async(&self) -> bool {
        true
    }
}

impl ServiceNameResolver for S3Record {
    fn get_specific_identifier(&self) -> String {
        self.s3.bucket.name.clone()
    }

    fn get_generic_identifier(&self) -> &'static str {
        "lambda_s3"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    #[test]
    fn test_new() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let result = S3Record::new(payload).expect("Failed to deserialize into Record");

        let expected = S3Record {
            event_source: String::from("aws:s3"),
            event_time: DateTime::parse_from_rfc3339("2023-01-07T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            event_name: String::from("ObjectCreated:Put"),
            s3: S3Entity {
                bucket: S3Bucket {
                    name: String::from("example-bucket"),
                    arn: String::from("arn:aws:s3:::example-bucket"),
                },
                object: S3Object {
                    key: String::from("test/key"),
                    size: Some(1024),
                    e_tag: Some(String::from("0123456789abcdef0123456789abcdef")),
                },
            },
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_is_match() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize S3Record");

        assert!(S3Record::is_match(&payload));
    }

    #[test]
    fn test_is_not_match() {
        let json = read_json_file("sqs_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize SqsRecord");
        assert!(!S3Record::is_match(&payload));
    }

    #[test]
    fn test_enrich_span() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize S3Record");
        let mut span = Span::default();
        let service_mapping = HashMap::new();
        event.enrich_span(&mut span, &service_mapping, true);
        assert_eq!(span.name, "aws.s3");
        assert_eq!(span.service, "example-bucket");
        assert_eq!(span.resource, "example-bucket");
        assert_eq!(span.r#type, "web");
        assert_eq!(span.start, 1_673_049_600_000_000_000);
    }

    #[test]
    fn test_get_tags() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize S3Record");
        let tags = event.get_tags();

        let expected = HashMap::from([(
            "function_trigger.event_source".to_string(),
            "s3".to_string(),
        )]);

        assert_eq!(tags, expected);
    }

    #[test]
    fn test_get_arn() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize S3Record");
        assert_eq!(
            event.get_arn("us-east-1", ""),
            "arn:aws:s3:::example-bucket"
        );
    }

    #[test]
    fn test_get_carrier() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize SqsRecord");
        let carrier = event.get_carrier();

        let expected = HashMap::new();

        assert_eq!(carrier, expected);
    }

    #[test]
    fn test_resolve_service_name_with_representation_enabled() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize S3Record");

        // Test 1: Specific mapping takes priority
        let specific_service_mapping = HashMap::from([
            ("example-bucket".to_string(), "specific-service".to_string()),
            ("lambda_s3".to_string(), "generic-service".to_string()),
        ]);

        let service = event.resolve_service_name(
            &specific_service_mapping,
            &event.get_specific_identifier(),
            "s3",
            true, // aws_service_representation_enabled
        );
        assert_eq!(service, "specific-service");

        // Test 2: Generic mapping is used when specific not found
        let generic_service_mapping =
            HashMap::from([("lambda_s3".to_string(), "generic-service".to_string())]);
        let service = event.resolve_service_name(
            &generic_service_mapping,
            &event.get_specific_identifier(),
            "s3",
            true, // aws_service_representation_enabled
        );
        assert_eq!(service, "generic-service");

        // Test 3: When no mapping exists, uses instance name (bucket name)
        let empty_mapping = HashMap::new();
        let service = event.resolve_service_name(
            &empty_mapping,
            &event.get_specific_identifier(),
            "s3",
            true, // aws_service_representation_enabled
        );
        assert_eq!(service, event.get_specific_identifier()); // instance name
    }

    #[test]
    fn test_resolve_service_name_with_representation_disabled() {
        let json = read_json_file("s3_event.json");
        let payload = serde_json::from_str(&json).expect("Failed to deserialize into Value");
        let event = S3Record::new(payload).expect("Failed to deserialize S3Record");

        // Test 1: With specific mapping - still respects mapping
        let specific_service_mapping = HashMap::from([
            ("example-bucket".to_string(), "specific-service".to_string()),
            ("lambda_s3".to_string(), "generic-service".to_string()),
        ]);

        let service = event.resolve_service_name(
            &specific_service_mapping,
            &event.get_specific_identifier(),
            "s3",
            false, // aws_service_representation_enabled = false
        );
        assert_eq!(service, "specific-service");

        // Test 2: With generic mapping - still respects mapping
        let generic_service_mapping =
            HashMap::from([("lambda_s3".to_string(), "generic-service".to_string())]);
        let service = event.resolve_service_name(
            &generic_service_mapping,
            &event.get_specific_identifier(),
            "s3",
            false, // aws_service_representation_enabled = false
        );
        assert_eq!(service, "generic-service");

        // Test 3: When no mapping exists, uses fallback value
        let empty_mapping = HashMap::new();
        let service = event.resolve_service_name(
            &empty_mapping,
            &event.get_specific_identifier(),
            "s3",
            false, // aws_service_representation_enabled = false
        );
        assert_eq!(service, "s3"); // fallback value
    }
}

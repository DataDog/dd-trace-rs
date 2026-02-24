// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! SNS-specific trace context enrichment.
//!
//! Injects trace context as a `_datadog` MessageAttribute (Binary DataType, JSON bytes)
//! into outgoing Publish and PublishBatch calls, matching dd-trace-go's format.
//! Binary format is used because SNS subscription filter policies fail silently
//! with JSON string values.

use std::collections::HashMap;

use aws_sdk_sns::operation::publish::PublishInput;
use aws_sdk_sns::operation::publish_batch::PublishBatchInput;
use aws_sdk_sns::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;
use aws_smithy_types::Blob;

use super::{AwsService, ServiceInjector, DATADOG_ATTRIBUTE_KEY, MAX_MESSAGE_ATTRIBUTES};

pub(crate) struct SnsInjector;

impl ServiceInjector for SnsInjector {
    fn service(&self) -> AwsService {
        AwsService::Sns
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        match operation {
            "Publish" => {
                if let Some(publish_input) = input.downcast_mut::<PublishInput>() {
                    inject_into_publish(publish_input, trace_headers)?;
                }
            }
            "PublishBatch" => {
                if let Some(batch_input) = input.downcast_mut::<PublishBatchInput>() {
                    inject_into_publish_batch(batch_input, trace_headers)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn inject_into_publish(
    input: &mut PublishInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let attrs = input.message_attributes.get_or_insert_with(HashMap::new);
    if attrs.len() >= MAX_MESSAGE_ATTRIBUTES {
        return Ok(());
    }

    attrs.insert(
        DATADOG_ATTRIBUTE_KEY.to_string(),
        build_datadog_attribute(trace_headers)?,
    );
    Ok(())
}

fn inject_into_publish_batch(
    input: &mut PublishBatchInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let entries = match input.publish_batch_request_entries.as_mut() {
        Some(entries) => entries,
        None => return Ok(()),
    };
    let dd_key = DATADOG_ATTRIBUTE_KEY.to_string();
    let dd_attr = build_datadog_attribute(trace_headers)?;
    for entry in entries.iter_mut() {
        let attrs = entry.message_attributes.get_or_insert_with(HashMap::new);
        if attrs.len() >= MAX_MESSAGE_ATTRIBUTES {
            continue;
        }
        attrs.insert(dd_key.clone(), dd_attr.clone());
    }
    Ok(())
}

fn build_datadog_attribute(
    trace_headers: &HashMap<String, String>,
) -> Result<MessageAttributeValue, BoxError> {
    let json_bytes = serde_json::to_vec(trace_headers)?;
    Ok(MessageAttributeValue::builder()
        .data_type("Binary")
        .binary_value(Blob::new(json_bytes))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::test_helpers::*;
    use aws_sdk_sns::types::PublishBatchRequestEntry;

    fn parse_binary_attr(attr: &MessageAttributeValue) -> HashMap<String, String> {
        assert_eq!(attr.data_type(), "Binary");
        let blob = attr.binary_value().unwrap();
        serde_json::from_slice(blob.as_ref()).unwrap()
    }

    #[test]
    fn test_publish_injection() {
        let trace_headers = sample_trace_headers();
        let mut input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .build()
            .unwrap();

        inject_into_publish(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn test_publish_batch_injection() {
        let trace_headers = sample_trace_headers();
        let entry1 = PublishBatchRequestEntry::builder()
            .id("1")
            .message("body1")
            .build()
            .unwrap();
        let entry2 = PublishBatchRequestEntry::builder()
            .id("2")
            .message("body2")
            .build()
            .unwrap();
        let mut input = PublishBatchInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .publish_batch_request_entries(entry1)
            .publish_batch_request_entries(entry2)
            .build()
            .unwrap();

        inject_into_publish_batch(&mut input, &trace_headers).unwrap();

        let entries = input.publish_batch_request_entries.as_ref().unwrap();
        for entry in entries {
            let attrs = entry.message_attributes.as_ref().unwrap();
            assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
            let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
            assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        }
    }

    #[test]
    fn test_max_attributes_skips_injection() {
        let trace_headers = sample_trace_headers();
        let mut builder = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message");
        for i in 0..10 {
            let attr = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(format!("value{i}"))
                .build()
                .unwrap();
            builder = builder.message_attributes(format!("attr{i}"), attr);
        }
        let mut input = builder.build().unwrap();

        inject_into_publish(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        assert!(!attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn test_batch_max_attributes_skips_per_entry() {
        let trace_headers = sample_trace_headers();
        let mut full_attrs = HashMap::new();
        for i in 0..10 {
            full_attrs.insert(
                format!("attr{i}"),
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(format!("value{i}"))
                    .build()
                    .unwrap(),
            );
        }
        let full_entry = PublishBatchRequestEntry::builder()
            .id("full")
            .message("body")
            .set_message_attributes(Some(full_attrs))
            .build()
            .unwrap();
        let empty_entry = PublishBatchRequestEntry::builder()
            .id("empty")
            .message("body")
            .build()
            .unwrap();
        let mut input = PublishBatchInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .publish_batch_request_entries(full_entry)
            .publish_batch_request_entries(empty_entry)
            .build()
            .unwrap();

        inject_into_publish_batch(&mut input, &trace_headers).unwrap();

        let entries = input.publish_batch_request_entries.as_ref().unwrap();
        let full = &entries[0];
        assert_eq!(full.message_attributes.as_ref().unwrap().len(), 10);
        assert!(!full
            .message_attributes
            .as_ref()
            .unwrap()
            .contains_key(DATADOG_ATTRIBUTE_KEY));

        let empty = &entries[1];
        assert!(empty
            .message_attributes
            .as_ref()
            .unwrap()
            .contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn test_unknown_operation_noop() {
        let trace_headers = sample_trace_headers();
        let injector = SnsInjector;
        let publish_input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .build()
            .unwrap();
        let mut input = Input::erase(publish_input);

        injector
            .inject("Subscribe", &trace_headers, &mut input)
            .unwrap();

        let publish_input = input.downcast_ref::<PublishInput>().unwrap();
        assert!(publish_input.message_attributes.is_none());
    }

    #[test]
    fn test_overwrites_existing_datadog_attribute() {
        let trace_headers = sample_trace_headers();
        let existing = MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(Blob::new(b"old".to_vec()))
            .build()
            .unwrap();
        let mut input = PublishInput::builder()
            .topic_arn("arn:aws:sns:us-east-1:123456789012:test-topic")
            .message("test message")
            .message_attributes(DATADOG_ATTRIBUTE_KEY, existing)
            .build()
            .unwrap();

        inject_into_publish(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        let parsed = parse_binary_attr(&attrs[DATADOG_ATTRIBUTE_KEY]);
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
    }
}

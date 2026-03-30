// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use aws_sdk_sqs::operation::delete_message::DeleteMessageInput;
use aws_sdk_sqs::operation::delete_message_batch::DeleteMessageBatchInput;
use aws_sdk_sqs::operation::receive_message::ReceiveMessageInput;
use aws_sdk_sqs::operation::send_message::SendMessageInput;
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;
use opentelemetry::KeyValue;

use crate::attribute_keys::{
    CLOUD_RESOURCE_ID, DATADOG_ATTRIBUTE_KEY, MESSAGING_SYSTEM, QUEUE_NAME,
};

use super::MAX_MESSAGE_ATTRIBUTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SqsOperation {
    SendMessage,
    SendMessageBatch,
    ReceiveMessage,
    DeleteMessage,
    DeleteMessageBatch,
}

impl SqsOperation {
    pub(super) fn from_name(operation: &str) -> Option<Self> {
        match operation {
            "SendMessage" => Some(Self::SendMessage),
            "SendMessageBatch" => Some(Self::SendMessageBatch),
            "ReceiveMessage" => Some(Self::ReceiveMessage),
            "DeleteMessage" => Some(Self::DeleteMessage),
            "DeleteMessageBatch" => Some(Self::DeleteMessageBatch),
            _ => None,
        }
    }
}

pub(super) fn inject(
    operation: SqsOperation,
    trace_headers: &HashMap<String, String>,
    input: &mut Input,
) -> Result<(), BoxError> {
    match operation {
        SqsOperation::SendMessage => {
            if let Some(send_input) = input.downcast_mut::<SendMessageInput>() {
                inject_into_send_message(send_input, trace_headers)?;
            }
        }
        SqsOperation::SendMessageBatch => {
            if let Some(batch_input) = input.downcast_mut::<SendMessageBatchInput>() {
                inject_into_send_message_batch(batch_input, trace_headers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn service_tags(
    operation: SqsOperation,
    input: &Input,
    region: &str,
    partition: &str,
) -> Vec<KeyValue> {
    let mut tags = vec![KeyValue::new(MESSAGING_SYSTEM, "amazonsqs")];

    let queue_url = match operation {
        SqsOperation::SendMessage => input
            .downcast_ref::<SendMessageInput>()
            .and_then(|r| r.queue_url.as_deref()),
        SqsOperation::SendMessageBatch => input
            .downcast_ref::<SendMessageBatchInput>()
            .and_then(|r| r.queue_url.as_deref()),
        SqsOperation::ReceiveMessage => input
            .downcast_ref::<ReceiveMessageInput>()
            .and_then(|r| r.queue_url.as_deref()),
        SqsOperation::DeleteMessage => input
            .downcast_ref::<DeleteMessageInput>()
            .and_then(|r| r.queue_url.as_deref()),
        SqsOperation::DeleteMessageBatch => input
            .downcast_ref::<DeleteMessageBatchInput>()
            .and_then(|r| r.queue_url.as_deref()),
    };

    if let Some((queue_name, cloud_resource_id)) =
        queue_url.and_then(|url| extract_sqs_metadata(url, region, partition))
    {
        tags.push(KeyValue::new(QUEUE_NAME, queue_name));
        tags.push(KeyValue::new(CLOUD_RESOURCE_ID, cloud_resource_id));
    }

    tags
}

fn inject_into_send_message(
    input: &mut SendMessageInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let attrs = input.message_attributes.get_or_insert_with(HashMap::new);
    if should_skip_injection(attrs) {
        return Ok(());
    }
    attrs.insert(
        DATADOG_ATTRIBUTE_KEY.to_string(),
        build_datadog_attribute(trace_headers)?,
    );
    Ok(())
}

fn inject_into_send_message_batch(
    input: &mut SendMessageBatchInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let Some(entries) = input.entries.as_mut() else {
        return Ok(());
    };
    let dd_key = DATADOG_ATTRIBUTE_KEY.to_string();
    let dd_attr = build_datadog_attribute(trace_headers)?;
    for entry in entries.iter_mut() {
        let attrs = entry.message_attributes.get_or_insert_with(HashMap::new);
        if should_skip_injection(attrs) {
            continue;
        }
        attrs.insert(dd_key.clone(), dd_attr.clone());
    }
    Ok(())
}

// Respect the 10-attribute cap unless replacing an existing _datadog attribute.
fn should_skip_injection(attrs: &HashMap<String, MessageAttributeValue>) -> bool {
    attrs.len() >= MAX_MESSAGE_ATTRIBUTES && !attrs.contains_key(DATADOG_ATTRIBUTE_KEY)
}

/// Returns `(queue_name, cloud_resource_id)` parsed from a SQS queue URL.
fn extract_sqs_metadata(
    queue_url: &str,
    region: &str,
    partition: &str,
) -> Option<(String, String)> {
    let queue_url = queue_url.trim_end_matches('/');
    let mut parts = queue_url.rsplitn(3, '/');
    let queue_name = parts.next()?;
    let account_id = parts.next()?;
    let cloud_resource_id = format!("arn:{partition}:sqs:{region}:{account_id}:{queue_name}");
    Some((queue_name.to_string(), cloud_resource_id))
}

fn build_datadog_attribute(
    trace_headers: &HashMap<String, String>,
) -> Result<MessageAttributeValue, BoxError> {
    let json = serde_json::to_string(trace_headers)?;
    Ok(MessageAttributeValue::builder()
        .data_type("String")
        .string_value(json)
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::test_helpers::{
        collect_string_tags, sample_trace_headers, DATADOG_PARENT_ID_KEY,
        DATADOG_SAMPLING_PRIORITY_KEY, DATADOG_TRACE_ID_KEY,
    };
    use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
    use aws_smithy_runtime_api::client::interceptors::context::Input;

    #[test]
    fn skips_injection_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut builder = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body");
        for i in 0..10 {
            let attr = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(format!("value{}", i))
                .build()
                .unwrap();
            builder = builder.message_attributes(format!("attr{}", i), attr);
        }
        let mut input = builder.build().unwrap();

        inject_into_send_message(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        assert!(!attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn overwrites_existing_datadog_attribute_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut builder = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body");
        for i in 0..9 {
            let attr = MessageAttributeValue::builder()
                .data_type("String")
                .string_value(format!("value{}", i))
                .build()
                .unwrap();
            builder = builder.message_attributes(format!("attr{}", i), attr);
        }
        let stale = MessageAttributeValue::builder()
            .data_type("String")
            .string_value("stale")
            .build()
            .unwrap();
        builder = builder.message_attributes(DATADOG_ATTRIBUTE_KEY, stale);
        let mut input = builder.build().unwrap();

        inject_into_send_message(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
        let json_str = dd_attr.string_value().unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn overwrites_existing_datadog_attribute_in_batch_entries_when_message_attributes_are_full() {
        let trace_headers = sample_trace_headers();
        let mut full_attrs = HashMap::new();
        for i in 0..9 {
            full_attrs.insert(
                format!("attr{i}"),
                MessageAttributeValue::builder()
                    .data_type("String")
                    .string_value(format!("value{i}"))
                    .build()
                    .unwrap(),
            );
        }
        full_attrs.insert(
            DATADOG_ATTRIBUTE_KEY.to_string(),
            MessageAttributeValue::builder()
                .data_type("String")
                .string_value("stale")
                .build()
                .unwrap(),
        );
        let entry = SendMessageBatchRequestEntry::builder()
            .id("full")
            .message_body("body")
            .set_message_attributes(Some(full_attrs))
            .build()
            .unwrap();
        let mut input = SendMessageBatchInput::builder()
            .queue_url("https://example.com/test-queue")
            .entries(entry)
            .build()
            .unwrap();

        inject_into_send_message_batch(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        let attrs = entries[0].message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
        let json_str = dd_attr.string_value().unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn unsupported_sqs_operation_returns_none() {
        assert!(SqsOperation::from_name("ListQueues").is_none());
    }
}

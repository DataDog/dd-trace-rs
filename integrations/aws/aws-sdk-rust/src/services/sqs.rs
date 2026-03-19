// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use aws_sdk_sqs::operation::send_message::SendMessageInput;
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

use crate::attribute_keys::{CLOUD_RESOURCE_ID, DATADOG_ATTRIBUTE_KEY, QUEUE_NAME};

use super::{base_request_metadata, AwsServiceHandler, RequestMetadata, MAX_MESSAGE_ATTRIBUTES};

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SqsService;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqsOperation {
    SendMessage,
    SendMessageBatch,
}

impl SqsOperation {
    fn from_name(operation: &str) -> Option<Self> {
        match operation {
            "SendMessage" => Some(Self::SendMessage),
            "SendMessageBatch" => Some(Self::SendMessageBatch),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SendMessage => "SendMessage",
            Self::SendMessageBatch => "SendMessageBatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqsRequestMetadata {
    queue_name: String,
    cloud_resource_id: String,
}

impl AwsServiceHandler for SqsService {
    fn service_id(&self) -> &'static str {
        "SQS"
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        inject(operation, trace_headers, input)
    }

    fn extract_request_metadata(
        &self,
        operation: &str,
        input: &Input,
        region: &str,
        partition: &str,
    ) -> Option<RequestMetadata> {
        let operation = SqsOperation::from_name(operation)?;
        let queue_url = match operation {
            SqsOperation::SendMessage => input
                .downcast_ref::<SendMessageInput>()
                .and_then(|request| request.queue_url.as_deref()),
            SqsOperation::SendMessageBatch => input
                .downcast_ref::<SendMessageBatchInput>()
                .and_then(|request| request.queue_url.as_deref()),
        }?;

        let sqs_metadata = extract_sqs_metadata(queue_url, region, partition)?;
        let mut request_metadata =
            base_request_metadata(self.service_id(), operation.name(), region, partition);
        request_metadata
            .tags
            .insert(QUEUE_NAME, sqs_metadata.queue_name);
        request_metadata
            .tags
            .insert(CLOUD_RESOURCE_ID, sqs_metadata.cloud_resource_id);
        Some(request_metadata)
    }
}

pub(super) fn inject(
    operation: &str,
    trace_headers: HashMap<String, String>,
    input: &mut Input,
) -> Result<(), BoxError> {
    match SqsOperation::from_name(operation) {
        Some(SqsOperation::SendMessage) => {
            if let Some(send_input) = input.downcast_mut::<SendMessageInput>() {
                inject_into_send_message(send_input, &trace_headers)?;
            }
        }
        Some(SqsOperation::SendMessageBatch) => {
            if let Some(batch_input) = input.downcast_mut::<SendMessageBatchInput>() {
                inject_into_send_message_batch(batch_input, &trace_headers)?;
            }
        }
        None => {}
    }
    Ok(())
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

fn should_skip_injection(attrs: &HashMap<String, MessageAttributeValue>) -> bool {
    attrs.len() >= MAX_MESSAGE_ATTRIBUTES && !attrs.contains_key(DATADOG_ATTRIBUTE_KEY)
}

fn extract_sqs_metadata(
    queue_url: &str,
    region: &str,
    partition: &str,
) -> Option<SqsRequestMetadata> {
    let queue_url = queue_url.trim_end_matches('/');
    let mut parts = queue_url.rsplitn(3, '/');
    let queue_name = parts.next()?;
    let account_id = parts.next()?;
    Some(SqsRequestMetadata {
        queue_name: queue_name.to_string(),
        cloud_resource_id: format!("arn:{partition}:sqs:{region}:{account_id}:{queue_name}"),
    })
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
        sample_trace_headers, DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY,
        DATADOG_TRACE_ID_KEY,
    };
    use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
    use aws_smithy_runtime_api::client::interceptors::context::Input;

    #[test]
    fn injects_trace_context_into_send_message() {
        let trace_headers = sample_trace_headers();
        let mut input = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body")
            .build()
            .unwrap();

        inject_into_send_message(&mut input, &trace_headers).unwrap();

        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
        let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
        assert_eq!(dd_attr.data_type(), "String");
        let json_str = dd_attr.string_value().unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        assert_eq!(parsed[DATADOG_PARENT_ID_KEY], "987654321");
        assert_eq!(parsed[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    #[test]
    fn injects_trace_context_into_send_message_batch() {
        let trace_headers = sample_trace_headers();
        let entry1 = SendMessageBatchRequestEntry::builder()
            .id("1")
            .message_body("body1")
            .build()
            .unwrap();
        let entry2 = SendMessageBatchRequestEntry::builder()
            .id("2")
            .message_body("body2")
            .build()
            .unwrap();
        let mut input = SendMessageBatchInput::builder()
            .queue_url("https://example.com/test-queue")
            .entries(entry1)
            .entries(entry2)
            .build()
            .unwrap();

        inject_into_send_message_batch(&mut input, &trace_headers).unwrap();

        let entries = input.entries.as_ref().unwrap();
        for entry in entries {
            let attrs = entry.message_attributes.as_ref().unwrap();
            assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
            let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
            assert_eq!(dd_attr.data_type(), "String");
            let json_str = dd_attr.string_value().unwrap();
            let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
            assert_eq!(parsed[DATADOG_TRACE_ID_KEY], "123456789");
        }
    }

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
    fn does_not_inject_for_unsupported_sqs_operations() {
        let trace_headers = sample_trace_headers();
        let send_input = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body")
            .build()
            .unwrap();
        let mut input = Input::erase(send_input);

        inject("ReceiveMessage", trace_headers, &mut input).unwrap();

        let send_input = input.downcast_ref::<SendMessageInput>().unwrap();
        assert!(send_input.message_attributes.is_none());
    }

    #[test]
    fn extracts_send_message_request_metadata() {
        let input = SendMessageInput::builder()
            .queue_url("https://sqs.eu-west-1.amazonaws.com/123456789012/MyQueueName")
            .message_body("hello")
            .build()
            .unwrap();
        let input = Input::erase(input);

        let metadata = SqsService
            .extract_request_metadata("SendMessage", &input, "eu-west-1", "aws")
            .unwrap();

        assert_eq!(metadata.service_name, "aws.SQS");
        assert_eq!(metadata.resource_name, "SQS.SendMessage");
        assert_eq!(metadata.tags[QUEUE_NAME], "MyQueueName");
        assert_eq!(
            metadata.tags[CLOUD_RESOURCE_ID],
            "arn:aws:sqs:eu-west-1:123456789012:MyQueueName"
        );
        assert_eq!(metadata.tags["aws.service"], "SQS");
        assert_eq!(metadata.tags["aws.operation"], "SendMessage");
        assert_eq!(metadata.tags["region"], "eu-west-1");
        assert_eq!(metadata.tags["aws.partition"], "aws");
        assert_eq!(metadata.tags["service.name"], "aws.SQS");
        assert_eq!(metadata.tags["resource.name"], "SQS.SendMessage");
    }

    #[test]
    fn extracts_send_message_batch_request_metadata() {
        let input = SendMessageBatchInput::builder()
            .queue_url("https://sqs.eu-west-1.amazonaws.com/123456789012/MyQueueName/")
            .build()
            .unwrap();
        let input = Input::erase(input);

        let metadata = SqsService
            .extract_request_metadata("SendMessageBatch", &input, "eu-west-1", "aws")
            .unwrap();

        assert_eq!(metadata.tags[QUEUE_NAME], "MyQueueName");
        assert_eq!(
            metadata.tags[CLOUD_RESOURCE_ID],
            "arn:aws:sqs:eu-west-1:123456789012:MyQueueName"
        );
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! SQS-specific trace context enrichment.
//!
//! Injects trace context as a `_datadog` MessageAttribute (JSON-serialized, DataType: String)
//! into outgoing SendMessage and SendMessageBatch calls, matching dd-trace-go's format.

use std::collections::HashMap;

use aws_sdk_sqs::operation::send_message::SendMessageInput;
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::Input;

use super::{AwsService, ServiceInjector, DATADOG_ATTRIBUTE_KEY};
const SQS_MAX_ATTRIBUTES: usize = 10;

pub(crate) struct SqsInjector;

impl ServiceInjector for SqsInjector {
    fn service(&self) -> AwsService {
        AwsService::Sqs
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut Input,
    ) -> Result<(), BoxError> {
        match operation {
            "SendMessage" => {
                if let Some(send_input) = input.downcast_mut::<SendMessageInput>() {
                    inject_into_send_message(send_input, trace_headers)?;
                }
            }
            "SendMessageBatch" => {
                if let Some(batch_input) = input.downcast_mut::<SendMessageBatchInput>() {
                    inject_into_send_message_batch(batch_input, trace_headers)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn inject_into_send_message(
    input: &mut SendMessageInput,
    trace_headers: &HashMap<String, String>,
) -> Result<(), BoxError> {
    let attrs = input.message_attributes.get_or_insert_with(HashMap::new);
    if attrs.len() >= SQS_MAX_ATTRIBUTES {
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
    let entries = match input.entries.as_mut() {
        Some(entries) => entries,
        None => return Ok(()),
    };
    let dd_key = DATADOG_ATTRIBUTE_KEY.to_string();
    let dd_attr = build_datadog_attribute(trace_headers)?;
    for entry in entries.iter_mut() {
        let attrs = entry.message_attributes.get_or_insert_with(HashMap::new);
        if attrs.len() >= SQS_MAX_ATTRIBUTES {
            continue;
        }
        attrs.insert(dd_key.clone(), dd_attr.clone());
    }
    Ok(())
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

    #[test]
    fn test_send_message_injection() {
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
    fn test_send_message_batch_injection() {
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
    fn test_max_attributes_skips_injection() {
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
    fn test_unknown_operation_noop() {
        let trace_headers = sample_trace_headers();
        let injector = SqsInjector;
        let send_input = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body")
            .build()
            .unwrap();
        let mut input = Input::erase(send_input);

        injector
            .inject("ReceiveMessage", &trace_headers, &mut input)
            .unwrap();

        let send_input = input.downcast_ref::<SendMessageInput>().unwrap();
        assert!(send_input.message_attributes.is_none());
    }
}

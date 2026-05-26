// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog trace context injection for AWS SDK for Rust SQS operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_sqs::SqsInterceptor;
//!
//! let config = aws_sdk_sqs::config::Builder::from(&sdk_config)
//!     .interceptor(SqsInterceptor::new())
//!     .build();
//! let client = aws_sdk_sqs::Client::from_conf(config);
//! ```

use std::collections::HashMap;

use aws_sdk_sqs::operation::delete_message::DeleteMessageInput;
use aws_sdk_sqs::operation::delete_message_batch::DeleteMessageBatchInput;
use aws_sdk_sqs::operation::receive_message::ReceiveMessageInput;
use aws_sdk_sqs::operation::send_message::SendMessageInput;
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::types::MessageAttributeValue;
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    BeforeSerializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    FinalizerInterceptorContextRef,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use opentelemetry::KeyValue;

use datadog_aws_core::attribute_keys::{
    CLOUD_RESOURCE_ID, DATADOG_ATTRIBUTE_KEY, MESSAGING_SYSTEM, QUEUE_NAME,
};
use datadog_aws_core::limits::MAX_MESSAGE_ATTRIBUTES;
use datadog_aws_core::{AwsInterceptor, ServiceHandler};

const TRACER_NAME: &str = "datadog-aws-sqs";

/// SQS operations that this interceptor recognises.
///
/// Only `SendMessage` and `SendMessageBatch` support trace context injection.
/// The remaining variants are tracked to produce accurate `operation.name` and
/// service tags without injecting into read/delete operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqsOperation {
    SendMessage,
    SendMessageBatch,
    ReceiveMessage,
    DeleteMessage,
    DeleteMessageBatch,
}

impl SqsOperation {
    /// Maps an SDK operation name string to the enum variant, or `None` for
    /// operations this interceptor does not handle.
    fn from_name(operation: &str) -> Option<Self> {
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

/// [`ServiceHandler`] implementation for Amazon SQS.
struct SqsHandler;

impl ServiceHandler for SqsHandler {
    fn sdk_service_name(&self) -> &'static str {
        "SQS"
    }

    fn span_service_id(&self) -> &'static str {
        "sqs"
    }

    fn inject(
        &self,
        operation: &str,
        trace_headers: &HashMap<String, String>,
        input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
    ) -> Result<(), BoxError> {
        if let Some(op) = SqsOperation::from_name(operation) {
            inject(op, trace_headers, input)?;
        }
        Ok(())
    }

    fn service_tags(
        &self,
        operation: &str,
        input: &aws_smithy_runtime_api::client::interceptors::context::Input,
        region: &str,
        partition: &str,
    ) -> Vec<KeyValue> {
        SqsOperation::from_name(operation)
            .map(|op| service_tags(op, input, region, partition))
            .unwrap_or_default()
    }
}

/// AWS SDK interceptor that injects Datadog trace context into SQS requests
/// and creates spans representing SQS operations.
#[derive(Debug)]
pub struct SqsInterceptor {
    inner: AwsInterceptor<SqsHandler>,
}

impl SqsInterceptor {
    pub fn new() -> Self {
        Self {
            inner: AwsInterceptor::new(SqsHandler, TRACER_NAME),
        }
    }
}

impl Default for SqsInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Intercept for SqsInterceptor {
    fn name(&self) -> &'static str {
        "SqsInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .modify_before_serialization(context, runtime_components, cfg)
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .read_before_transmit(context, runtime_components, cfg)
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        self.inner
            .read_after_execution(context, runtime_components, cfg)
    }
}

/// Dispatches trace context injection to the appropriate per-operation function.
///
/// Only `SendMessage` and `SendMessageBatch` carry a message attributes payload
/// that supports injection; all other operations are no-ops.
fn inject(
    operation: SqsOperation,
    trace_headers: &HashMap<String, String>,
    input: &mut aws_smithy_runtime_api::client::interceptors::context::Input,
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

/// Returns SQS-specific span tags for the given operation.
///
/// Always includes `messaging.system = "amazonsqs"`. When a queue URL is
/// available on the input, also includes `queuename` and `cloud.resource_id`
/// (formatted as a full SQS ARN).
fn service_tags(
    operation: SqsOperation,
    input: &aws_smithy_runtime_api::client::interceptors::context::Input,
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

/// Injects a `_datadog` String message attribute into a `SendMessage` input.
///
/// Skipped when the message already has 10 attributes and none is `_datadog`
/// (replacing an existing `_datadog` key is always allowed).
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

/// Injects a `_datadog` String message attribute into each entry of a `SendMessageBatch` input.
///
/// The same skip/overwrite rules as [`inject_into_send_message`] apply per entry.
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

/// Returns `true` when injection should be skipped to respect the 10-attribute cap.
///
/// An existing `_datadog` attribute counts as a slot we can reuse, so the cap
/// is only enforced when `_datadog` is absent.
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

/// Serialises `trace_headers` as a JSON String-typed SQS message attribute.
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
    use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        sample_trace_headers, DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY,
        DATADOG_TRACE_ID_KEY,
    };

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

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog tracing for AWS SDK for Rust SQS operations.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws_sqs::ConfigExt as _;
//!
//! let config = aws_sdk_sqs::config::Builder::from(&sdk_config)
//!     .datadog_tracing()
//!     .build();
//! let client = aws_sdk_sqs::Client::from_conf(config);
//! ```

use std::collections::HashMap;

use aws_sdk_sqs::operation::delete_message::DeleteMessageInput;
use aws_sdk_sqs::operation::delete_message_batch::DeleteMessageBatchInput;
use aws_sdk_sqs::operation::receive_message::{ReceiveMessageInput, ReceiveMessageOutput};
use aws_sdk_sqs::operation::send_message::{SendMessageInput, SendMessageOutput};
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::types::{Message, MessageAttributeValue};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    AfterDeserializationInterceptorContextRef, BeforeSerializationInterceptorContextMut,
    BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef, Input,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{global, otel_debug, Context, KeyValue};

use datadog_aws_core as aws_core;
use datadog_aws_core::attribute_keys::{
    CLOUD_RESOURCE_ID, DATADOG_ATTRIBUTE_KEY, MESSAGING_SYSTEM, QUEUE_NAME,
};

const TRACER_NAME: &str = "datadog-aws-sqs";
const SPAN_NAME: &str = "sqs.request";
const SPAN_OPERATION_NAME: &str = "aws.sqs.request";
const MAX_MESSAGE_ATTRIBUTES: usize = 10;
const MESSAGING_MESSAGE_ID: &str = "messaging.message.id";
const MESSAGING_BATCH_MESSAGE_COUNT: &str = "messaging.batch.message_count";
const SQS_RECEIVE_MESSAGES_EVENT: &str = "sqs.receive.messages";

/// AWS SDK interceptor that creates Datadog spans and injects trace context into SQS requests.
///
/// Use [`ConfigExt::datadog_tracing`] to install it on an SQS config builder.
#[derive(Debug)]
struct SqsInterceptor {
    tracer: global::BoxedTracer,
}

impl SqsInterceptor {
    fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

/// Extension methods for installing Datadog tracing on an Amazon SQS config builder.
pub trait ConfigExt {
    /// Installs Datadog tracing on this SQS config builder.
    fn datadog_tracing(self) -> Self;
}

impl ConfigExt for aws_sdk_sqs::config::Builder {
    fn datadog_tracing(self) -> Self {
        self.interceptor(SqsInterceptor::new())
    }
}

/// Extracts an OpenTelemetry context from an SQS message's `_datadog` message attribute.
///
/// Returns `None` when the message does not contain a valid Datadog propagation attribute.
pub fn extract_context(message: &Message) -> Option<Context> {
    let attrs = message.message_attributes.as_ref()?;
    let datadog_attr = attrs.get(DATADOG_ATTRIBUTE_KEY)?;
    let Some(json) = datadog_attr.string_value() else {
        otel_debug!(
            name: "Sqs.Extract.DatadogAttributeNotString",
            action = "context extraction skipped",
        );
        return None;
    };

    let trace_headers: HashMap<String, String> = match serde_json::from_str(json) {
        Ok(headers) => headers,
        Err(err) => {
            otel_debug!(
                name: "Sqs.Extract.DatadogAttributeParseFailed",
                reason = err.to_string(),
                action = "context extraction skipped",
            );
            return None;
        }
    };

    let context = global::get_text_map_propagator(|propagator| propagator.extract(&trace_headers));

    context.span().span_context().is_valid().then_some(context)
}

impl Intercept for SqsInterceptor {
    fn name(&self) -> &'static str {
        "SqsInterceptor"
    }

    fn modify_before_serialization(
        &self,
        context: &mut BeforeSerializationInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        let Some(metadata) = aws_core::AwsRequestMetadata::from_config_bag(cfg) else {
            return Ok(());
        };

        let input = context.input();
        let mut queue_url = None;
        if let Some(input) = input.downcast_ref::<SendMessageInput>() {
            queue_url = input.queue_url.as_deref();
        } else if let Some(input) = input.downcast_ref::<SendMessageBatchInput>() {
            queue_url = input.queue_url.as_deref();
        } else if let Some(input) = input.downcast_ref::<ReceiveMessageInput>() {
            queue_url = input.queue_url.as_deref();
        } else if let Some(input) = input.downcast_ref::<DeleteMessageInput>() {
            queue_url = input.queue_url.as_deref();
        } else if let Some(input) = input.downcast_ref::<DeleteMessageBatchInput>() {
            queue_url = input.queue_url.as_deref();
        }
        let mut queue_name = None;
        let mut cloud_resource_id = None;
        if let Some(url) = queue_url {
            let url = url.trim_end_matches('/');
            let mut parts = url.rsplit('/');
            if let (Some(name), Some(account_id)) = (parts.next(), parts.next()) {
                queue_name = Some(name);
                let region = &metadata.region;
                let partition = metadata.partition;
                cloud_resource_id =
                    Some(format!("arn:{partition}:sqs:{region}:{account_id}:{name}"));
            }
        }
        let service_tags = [
            Some(KeyValue::new(MESSAGING_SYSTEM, "amazonsqs")),
            queue_name.map(|name| KeyValue::new(QUEUE_NAME, name.to_string())),
            cloud_resource_id.map(|id| KeyValue::new(CLOUD_RESOURCE_ID, id)),
        ]
        .into_iter()
        .flatten();

        let span_context = aws_core::start_request_span(
            SPAN_NAME,
            SPAN_OPERATION_NAME,
            metadata,
            service_tags,
            &self.tracer,
            cfg,
        );
        inject(&span_context, context.input_mut());
        include_datadog_attribute_for_receive(context.input_mut());

        Ok(())
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        aws_core::update_request_span(context, cfg);
        Ok(())
    }

    fn read_after_deserialization(
        &self,
        context: &AfterDeserializationInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        fn message_id_attribute(message_id: &str) -> KeyValue {
            KeyValue::new(MESSAGING_MESSAGE_ID, message_id.to_string())
        }

        let Ok(output) = context.output_or_error() else {
            return Ok(());
        };

        let Some(request_span_context) = aws_core::request_span_context(cfg) else {
            return Ok(());
        };

        if let Some(output) = output.downcast_ref::<SendMessageOutput>() {
            if let Some(message_id) = output.message_id() {
                request_span_context
                    .span()
                    .set_attributes([message_id_attribute(message_id)]);
            }
        } else if let Some(output) = output.downcast_ref::<ReceiveMessageOutput>() {
            let messages = output.messages();
            request_span_context.span().add_event(
                SQS_RECEIVE_MESSAGES_EVENT,
                vec![KeyValue::new(
                    MESSAGING_BATCH_MESSAGE_COUNT,
                    messages.len() as i64,
                )],
            );

            for message in messages {
                if let Some(message_context) = extract_context(message) {
                    let message_span_context = message_context.span().span_context().clone();
                    request_span_context.span().add_link(
                        message_span_context,
                        message
                            .message_id()
                            .map(message_id_attribute)
                            .into_iter()
                            .collect(),
                    );
                }
            }
        }

        Ok(())
    }

    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        aws_core::finish_request_span(context, cfg);
        Ok(())
    }
}

/// Dispatches trace context injection based on the concrete operation input type.
///
/// Only `SendMessage` and `SendMessageBatch` carry a message attributes payload
/// that supports injection; all other operations are no-ops.
fn inject(span_context: &Context, input: &mut Input) {
    if let Some(send_input) = input.downcast_mut::<SendMessageInput>() {
        if let Some(dd_attr) = build_datadog_attribute(span_context) {
            inject_message_attribute(&mut send_input.message_attributes, dd_attr);
        }
    } else if let Some(batch_input) = input.downcast_mut::<SendMessageBatchInput>() {
        if let Some(entries) = batch_input.entries.as_mut() {
            if let Some(dd_attr) = build_datadog_attribute(span_context) {
                for entry in entries.iter_mut() {
                    inject_message_attribute(&mut entry.message_attributes, dd_attr.clone());
                }
            }
        }
    }
}

fn include_datadog_attribute_for_receive(input: &mut Input) {
    let Some(receive_input) = input.downcast_mut::<ReceiveMessageInput>() else {
        return;
    };

    let names = receive_input
        .message_attribute_names
        .get_or_insert_with(Vec::new);

    if names
        .iter()
        .any(|name| name == DATADOG_ATTRIBUTE_KEY || name == "All" || name == ".*")
    {
        return;
    }

    names.push(DATADOG_ATTRIBUTE_KEY.to_string());
}

fn build_datadog_attribute(span_context: &Context) -> Option<MessageAttributeValue> {
    let trace_headers = aws_core::request_span_trace_headers(span_context);
    if trace_headers.is_empty() {
        return None;
    }

    let attribute = || -> Result<MessageAttributeValue, BoxError> {
        let json = serde_json::to_string(&trace_headers)?;
        MessageAttributeValue::builder()
            .data_type("String")
            .string_value(json)
            .build()
            .map_err(Into::into)
    };

    match attribute() {
        Ok(attr) => Some(attr),
        Err(err) => {
            otel_debug!(
                name: "Sqs.Inject.DatadogAttributeBuildFailed",
                reason = err.to_string(),
                action = "context injection skipped",
            );
            None
        }
    }
}

fn inject_message_attribute(
    message_attributes: &mut Option<HashMap<String, MessageAttributeValue>>,
    datadog_attr: MessageAttributeValue,
) {
    let attrs = message_attributes.get_or_insert_with(HashMap::new);
    if attrs.len() < MAX_MESSAGE_ATTRIBUTES || attrs.contains_key(DATADOG_ATTRIBUTE_KEY) {
        attrs.insert(DATADOG_ATTRIBUTE_KEY.to_string(), datadog_attr);
    } else {
        otel_debug!(
            name: "Sqs.Inject.MessageAttributesFull",
            max_message_attributes = MAX_MESSAGE_ATTRIBUTES,
            action = "context injection skipped",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sqs::types::SendMessageBatchRequestEntry;
    use datadog_aws_core_test_utils::test_helpers::{
        ensure_test_propagator, test_context, TEST_CONTEXT_INJECTED_KEY,
    };

    #[test]
    fn skips_injection_when_message_attributes_are_full() {
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
        let mut input = Input::erase(builder.build().unwrap());

        inject(&Context::new(), &mut input);

        let input = input.downcast_ref::<SendMessageInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        assert!(!attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn overwrites_existing_datadog_attribute_when_message_attributes_are_full() {
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
        let mut input = Input::erase(builder.build().unwrap());

        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<SendMessageInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
        let json_str = dd_attr.string_value().unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed[TEST_CONTEXT_INJECTED_KEY], "true");
    }

    #[test]
    fn overwrites_existing_datadog_attribute_in_batch_entries_when_message_attributes_are_full() {
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
        let mut input = Input::erase(
            SendMessageBatchInput::builder()
                .queue_url("https://example.com/test-queue")
                .entries(entry)
                .build()
                .unwrap(),
        );

        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<SendMessageBatchInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        let attrs = entries[0].message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let dd_attr = &attrs[DATADOG_ATTRIBUTE_KEY];
        let json_str = dd_attr.string_value().unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed[TEST_CONTEXT_INJECTED_KEY], "true");
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let input = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body")
            .build()
            .unwrap();
        let mut input = Input::erase(input);

        ensure_test_propagator();
        inject(&test_context(), &mut input);

        let input = input.downcast_ref::<SendMessageInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn extract_context_reads_datadog_message_attribute() {
        datadog_aws_core_test_utils::integration_test_helpers::init_test_tracer();
        let datadog_attr = MessageAttributeValue::builder()
            .data_type("String")
            .string_value(
                serde_json::json!({
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
                })
                .to_string(),
            )
            .build()
            .unwrap();
        let message = Message::builder()
            .message_attributes(DATADOG_ATTRIBUTE_KEY, datadog_attr)
            .build();
        let extracted = extract_context(&message).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_returns_none_with_invalid_trace_context() {
        datadog_aws_core_test_utils::integration_test_helpers::init_test_tracer();
        let datadog_attr = MessageAttributeValue::builder()
            .data_type("String")
            .string_value(serde_json::json!({ "traceparent": "invalid" }).to_string())
            .build()
            .unwrap();
        let message = Message::builder()
            .message_attributes(DATADOG_ATTRIBUTE_KEY, datadog_attr)
            .build();

        assert!(extract_context(&message).is_none());
    }

    #[test]
    fn extract_context_returns_none_without_datadog_message_attribute() {
        let message = Message::builder().build();

        assert!(extract_context(&message).is_none());
    }

    #[test]
    fn include_datadog_attribute_for_receive_when_missing() {
        let input = ReceiveMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .build()
            .unwrap();
        let mut input = Input::erase(input);

        include_datadog_attribute_for_receive(&mut input);

        let input = input.downcast_ref::<ReceiveMessageInput>().unwrap();
        assert_eq!(
            input.message_attribute_names.as_deref(),
            Some(&[DATADOG_ATTRIBUTE_KEY.to_string()][..])
        );
    }
}

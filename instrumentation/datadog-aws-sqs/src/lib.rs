// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Datadog tracing for AWS SDK for Rust SQS operations.
//!
//! # What it instruments
//!
//! Installing [`ConfigExt::datadog_tracing`] adds an AWS SDK interceptor that creates one
//! `sqs.request` client span for each SQS SDK operation as a child of the current OpenTelemetry
//! context. Spans are tagged with common AWS SDK metadata, HTTP method, URL, user agent, response
//! status, AWS request ID, and SDK errors.
//!
//! SQS-specific span tags include `messaging.system = amazonsqs`, `queuename`,
//! `cloud.resource_id`, `messaging.batch.message_count`, and the sent `messaging.message.id` when
//! available.
//!
//! For `SendMessage` and `SendMessageBatch`, the interceptor injects the active request span
//! context as an SQS message attribute named `_datadog` with data type `String`. Existing
//! `_datadog` attributes are replaced. Injection is skipped when the message already has the
//! maximum number of SQS message attributes and no `_datadog` attribute is present.
//!
//! For `ReceiveMessage`, the interceptor requests the `_datadog` message attribute if the caller
//! did not already request it. After messages are received, the request span records the received
//! message count, adds an `sqs.receive.messages` event, and links the request span to extracted
//! producer contexts found in SQS message attributes, SNS notification envelopes, EventBridge
//! envelopes, or EventBridge envelopes nested inside SNS notifications. Use [`extract_context`] to
//! extract the same parent context when starting consumer work for a specific message.
//!
//! # Payload Size Headroom
//!
//! Datadog trace context is injected into AWS payload fields before the SDK sends the request, so
//! applications should leave a small amount of room under the SQS message size limit. With the
//! default W3C trace-context propagator, the JSON attribute value is typically less than 100 bytes
//! before AWS request serialization overhead. Baggage from the configured global OpenTelemetry
//! text-map propagator can add arbitrary bytes. SQS performs the authoritative size validation, and
//! this crate only applies cheap stable guards such as the message attribute count limit.
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

use std::borrow::Cow;
use std::collections::HashMap;

use aws_sdk_sqs::operation::add_permission::AddPermissionInput;
use aws_sdk_sqs::operation::change_message_visibility::ChangeMessageVisibilityInput;
use aws_sdk_sqs::operation::change_message_visibility_batch::ChangeMessageVisibilityBatchInput;
use aws_sdk_sqs::operation::delete_message::DeleteMessageInput;
use aws_sdk_sqs::operation::delete_message_batch::DeleteMessageBatchInput;
use aws_sdk_sqs::operation::delete_queue::DeleteQueueInput;
use aws_sdk_sqs::operation::get_queue_attributes::GetQueueAttributesInput;
use aws_sdk_sqs::operation::list_dead_letter_source_queues::ListDeadLetterSourceQueuesInput;
use aws_sdk_sqs::operation::list_queue_tags::ListQueueTagsInput;
use aws_sdk_sqs::operation::purge_queue::PurgeQueueInput;
use aws_sdk_sqs::operation::receive_message::{ReceiveMessageInput, ReceiveMessageOutput};
use aws_sdk_sqs::operation::remove_permission::RemovePermissionInput;
use aws_sdk_sqs::operation::send_message::{SendMessageInput, SendMessageOutput};
use aws_sdk_sqs::operation::send_message_batch::SendMessageBatchInput;
use aws_sdk_sqs::operation::set_queue_attributes::SetQueueAttributesInput;
use aws_sdk_sqs::operation::tag_queue::TagQueueInput;
use aws_sdk_sqs::operation::untag_queue::UntagQueueInput;
use aws_sdk_sqs::types::{Message, MessageAttributeValue};
use aws_smithy_runtime_api::box_error::BoxError;
use aws_smithy_runtime_api::client::interceptors::context::{
    AfterDeserializationInterceptorContextRef, BeforeSerializationInterceptorContextMut,
    BeforeTransmitInterceptorContextRef, FinalizerInterceptorContextRef, Input,
};
use aws_smithy_runtime_api::client::interceptors::Intercept;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::config_bag::ConfigBag;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TraceContextExt;
use opentelemetry::{global, Context, KeyValue};
use serde::Deserialize;
use serde_json::Value;

use datadog_aws_core::{
    attribute_keys::{
        CLOUD_RESOURCE_ID, DATADOG_ATTRIBUTE_KEY, MESSAGING_BATCH_MESSAGE_COUNT, MESSAGING_SYSTEM,
        QUEUE_NAME,
    },
    finish_request_span, request_span_context, request_span_trace_headers, start_request_span,
    update_request_span, AwsRequestMetadata,
};

const TRACER_NAME: &str = "datadog-aws-sqs";
const SPAN_NAME: &str = "sqs.request";
const SPAN_OPERATION_NAME: &str = "aws.sqs.request";
const MAX_MESSAGE_ATTRIBUTES: usize = 10;
const MESSAGING_MESSAGE_ID: &str = "messaging.message.id";
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

/// Extracts an OpenTelemetry context from an SQS message.
///
/// Context is read from the SQS `_datadog` message attribute when present, from the
/// `_datadog` attribute inside an SNS notification envelope in the message body,
/// from the `_datadog` field inside the `detail` object of an EventBridge envelope,
/// or from an EventBridge event inside an SNS notification's `Message` field.
///
/// Returns `None` when the message does not contain a valid Datadog propagation attribute.
pub fn extract_context(message: &Message) -> Option<Context> {
    let trace_headers = datadog_trace_headers(message)?;
    global::get_text_map_propagator(|propagator| {
        extract_context_from_trace_headers(&trace_headers, propagator)
    })
}

#[cfg(test)]
fn extract_context_with_propagator(
    message: &Message,
    propagator: &dyn TextMapPropagator,
) -> Option<Context> {
    let trace_headers = datadog_trace_headers(message)?;
    extract_context_from_trace_headers(&trace_headers, propagator)
}

fn datadog_trace_headers(message: &Message) -> Option<HashMap<String, String>> {
    if let Some(datadog_attr) = message
        .message_attributes
        .as_ref()
        .and_then(|attrs| attrs.get(DATADOG_ATTRIBUTE_KEY))
    {
        return trace_headers_from_sqs_message_attribute(datadog_attr);
    }

    trace_headers_from_sns_envelope(message)
        .or_else(|| trace_headers_from_eventbridge_envelope(message))
}

fn trace_headers_from_sqs_message_attribute(
    datadog_attr: &MessageAttributeValue,
) -> Option<HashMap<String, String>> {
    if let Some(json) = datadog_attr.string_value() {
        parse_trace_headers_from_str(json, "Sqs.Extract.DatadogAttributeParseFailed")
    } else if let Some(bytes) = datadog_attr.binary_value() {
        parse_trace_headers_from_slice(
            bytes.as_ref(),
            "Sqs.Extract.DatadogBinaryAttributeParseFailed",
        )
    } else {
        tracing::debug!(
            name: "Sqs.Extract.DatadogAttributeMissingValue",
            action = "context extraction skipped",
        );
        None
    }
}

fn trace_headers_from_sns_envelope(message: &Message) -> Option<HashMap<String, String>> {
    let body = message.body()?;
    if !body.contains(DATADOG_ATTRIBUTE_KEY)
        || (!body.contains("\"MessageAttributes\"") && !body.contains("\"Message\""))
    {
        return None;
    }

    let envelope = match sns_envelope(body) {
        Ok(envelope) => envelope,
        Err(err) => {
            tracing::debug!(
                name: "Sqs.Extract.SnsEnvelopeParseFailed",
                reason = %err,
                action = "context extraction skipped",
            );
            return None;
        }
    };

    let datadog_attr = match envelope
        .message_attributes
        .and_then(|attributes| attributes.datadog)
    {
        Some(datadog_attr) => datadog_attr,
        None => {
            return envelope
                .message
                .as_deref()
                .and_then(trace_headers_from_eventbridge_body);
        }
    };

    trace_headers_from_sns_datadog_attribute(datadog_attr)
}

fn trace_headers_from_sns_datadog_attribute(
    datadog_attr: SnsEnvelopeDatadogAttribute<'_>,
) -> Option<HashMap<String, String>> {
    match datadog_attr.data_type.as_ref() {
        "Binary" => {
            let bytes = match BASE64_STANDARD.decode(datadog_attr.value.as_ref()) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::debug!(
                        name: "Sqs.Extract.SnsEnvelopeDatadogBinaryDecodeFailed",
                        reason = %err,
                        action = "context extraction skipped",
                    );
                    return None;
                }
            };
            parse_trace_headers_from_slice(
                &bytes,
                "Sqs.Extract.SnsEnvelopeDatadogBinaryAttributeParseFailed",
            )
        }
        "String" => parse_trace_headers_from_str(
            datadog_attr.value.as_ref(),
            "Sqs.Extract.SnsEnvelopeDatadogAttributeParseFailed",
        ),
        data_type => {
            tracing::debug!(
                name: "Sqs.Extract.SnsEnvelopeDatadogAttributeUnsupportedType",
                data_type,
                action = "context extraction skipped",
            );
            None
        }
    }
}

fn trace_headers_from_eventbridge_body(body: &str) -> Option<HashMap<String, String>> {
    match eventbridge_envelope_datadog_attribute(body) {
        Ok(Some(trace_headers)) => Some(trace_headers),
        Ok(None) => None,
        Err(err) => {
            tracing::debug!(
                name: "Sqs.Extract.EventBridgeEnvelopeParseFailed",
                reason = %err,
                action = "context extraction skipped",
            );
            None
        }
    }
}

#[derive(Deserialize)]
struct SnsEnvelope<'a> {
    #[serde(rename = "MessageAttributes", borrow)]
    message_attributes: Option<SnsMessageAttributes<'a>>,
    #[serde(rename = "Message", borrow)]
    message: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct SnsMessageAttributes<'a> {
    #[serde(rename = "_datadog", borrow)]
    datadog: Option<SnsEnvelopeDatadogAttribute<'a>>,
}

#[derive(Deserialize)]
struct SnsEnvelopeDatadogAttribute<'a> {
    #[serde(rename = "Type", borrow)]
    data_type: Cow<'a, str>,
    #[serde(rename = "Value", borrow)]
    value: Cow<'a, str>,
}

fn sns_envelope(body: &str) -> Result<SnsEnvelope<'_>, serde_json::Error> {
    serde_json::from_str(body)
}

fn trace_headers_from_eventbridge_envelope(message: &Message) -> Option<HashMap<String, String>> {
    let body = message.body()?;
    if !body.contains(DATADOG_ATTRIBUTE_KEY) || !body.contains("\"detail\"") {
        return None;
    }

    trace_headers_from_eventbridge_body(body)
}

#[derive(Deserialize)]
struct EventBridgeEnvelope {
    detail: Option<Value>,
}

fn eventbridge_envelope_datadog_attribute(
    body: &str,
) -> Result<Option<HashMap<String, String>>, serde_json::Error> {
    let envelope: EventBridgeEnvelope = serde_json::from_str(body)?;
    Ok(envelope.detail.as_ref().and_then(trace_headers_from_detail))
}

fn trace_headers_from_detail(detail: &Value) -> Option<HashMap<String, String>> {
    detail
        .as_object()
        .and_then(|detail| detail.get(DATADOG_ATTRIBUTE_KEY))
        .and_then(trace_headers_from_datadog_value)
}

fn trace_headers_from_datadog_value(value: &Value) -> Option<HashMap<String, String>> {
    match value {
        Value::Object(_) => serde_json::from_value(value.clone()).ok(),
        Value::String(json_or_base64) => parse_trace_headers_from_str_or_base64(
            json_or_base64,
            "Sqs.Extract.EventBridgeDatadogAttributeParseFailed",
            "Sqs.Extract.EventBridgeDatadogBinaryAttributeParseFailed",
        ),
        _ => None,
    }
}

fn parse_trace_headers_from_str_or_base64(
    json_or_base64: &str,
    json_failure_name: &'static str,
    binary_failure_name: &'static str,
) -> Option<HashMap<String, String>> {
    match serde_json::from_str(json_or_base64) {
        Ok(headers) => Some(headers),
        Err(json_err) => match BASE64_STANDARD.decode(json_or_base64) {
            Ok(bytes) => parse_trace_headers_from_slice(&bytes, binary_failure_name),
            Err(base64_err) => {
                tracing::debug!(
                    name = json_failure_name,
                    reason = %json_err,
                    action = "context extraction skipped",
                );
                tracing::debug!(
                    name = binary_failure_name,
                    reason = %base64_err,
                    action = "context extraction skipped",
                );
                None
            }
        },
    }
}

fn parse_trace_headers_from_str(
    json: &str,
    failure_name: &'static str,
) -> Option<HashMap<String, String>> {
    match serde_json::from_str(json) {
        Ok(headers) => Some(headers),
        Err(err) => {
            tracing::debug!(
                name = failure_name,
                reason = %err,
                action = "context extraction skipped",
            );
            None
        }
    }
}

fn parse_trace_headers_from_slice(
    json: &[u8],
    failure_name: &'static str,
) -> Option<HashMap<String, String>> {
    match serde_json::from_slice(json) {
        Ok(headers) => Some(headers),
        Err(err) => {
            tracing::debug!(
                name = failure_name,
                reason = %err,
                action = "context extraction skipped",
            );
            None
        }
    }
}
fn extract_context_from_trace_headers(
    trace_headers: &HashMap<String, String>,
    propagator: &dyn TextMapPropagator,
) -> Option<Context> {
    let context = propagator.extract(trace_headers);

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
        let Some(metadata) = AwsRequestMetadata::from_config_bag(cfg) else {
            return Ok(());
        };

        let input = context.input();
        let queue_url = queue_url_from_input(input);
        let batch_message_count = batch_message_count_from_input(input);
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
            batch_message_count.map(|count| KeyValue::new(MESSAGING_BATCH_MESSAGE_COUNT, count)),
        ]
        .into_iter()
        .flatten();

        let span_context = start_request_span(
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
        update_request_span(context, cfg);
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

        let Some(request_span_context) = request_span_context(cfg) else {
            return Ok(());
        };
        let request_span = request_span_context.span();

        if let Some(output) = output.downcast_ref::<SendMessageOutput>() {
            if let Some(message_id) = output.message_id() {
                request_span.set_attributes([message_id_attribute(message_id)]);
            }
        } else if let Some(output) = output.downcast_ref::<ReceiveMessageOutput>() {
            let messages = output.messages();
            request_span.set_attributes([KeyValue::new(
                MESSAGING_BATCH_MESSAGE_COUNT,
                messages.len() as i64,
            )]);
            request_span.add_event(SQS_RECEIVE_MESSAGES_EVENT, Vec::new());

            for message in messages {
                if let Some(message_context) = extract_context(message) {
                    let message_span_context = message_context.span().span_context().clone();
                    request_span.add_link(
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
        finish_request_span(context, cfg);
        Ok(())
    }
}

fn queue_url_from_input(input: &Input) -> Option<&str> {
    if let Some(input) = input.downcast_ref::<AddPermissionInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<ChangeMessageVisibilityInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<ChangeMessageVisibilityBatchInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<DeleteMessageInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<DeleteMessageBatchInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<DeleteQueueInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<GetQueueAttributesInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<ListDeadLetterSourceQueuesInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<ListQueueTagsInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<PurgeQueueInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<ReceiveMessageInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<RemovePermissionInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<SendMessageInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<SendMessageBatchInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<SetQueueAttributesInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<TagQueueInput>() {
        input.queue_url.as_deref()
    } else if let Some(input) = input.downcast_ref::<UntagQueueInput>() {
        input.queue_url.as_deref()
    } else {
        None
    }
}

fn batch_message_count_from_input(input: &Input) -> Option<i64> {
    if let Some(input) = input.downcast_ref::<SendMessageBatchInput>() {
        return Some(input.entries.as_ref().map_or(0, Vec::len) as i64);
    }

    input
        .downcast_ref::<DeleteMessageBatchInput>()
        .map(|input| input.entries.as_ref().map_or(0, Vec::len) as i64)
}

/// Dispatches trace context injection based on the concrete operation input type.
///
/// Only `SendMessage` and `SendMessageBatch` carry a message attributes payload
/// that supports injection; all other operations are no-ops.
fn inject(span_context: &Context, input: &mut Input) {
    inject_with_trace_headers(input, || request_span_trace_headers(span_context));
}

fn inject_with_trace_headers(
    input: &mut Input,
    trace_headers: impl FnOnce() -> HashMap<String, String>,
) {
    if let Some(send_input) = input.downcast_mut::<SendMessageInput>() {
        let trace_headers = trace_headers();
        if let Some(dd_attr) = build_datadog_attribute(&trace_headers) {
            inject_message_attribute(&mut send_input.message_attributes, dd_attr);
        }
    } else if let Some(batch_input) = input.downcast_mut::<SendMessageBatchInput>() {
        if let Some(entries) = batch_input.entries.as_mut() {
            let trace_headers = trace_headers();
            if let Some(dd_attr) = build_datadog_attribute(&trace_headers) {
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

fn build_datadog_attribute(
    trace_headers: &HashMap<String, String>,
) -> Option<MessageAttributeValue> {
    if trace_headers.is_empty() {
        return None;
    }

    let attribute = || -> Result<MessageAttributeValue, BoxError> {
        let json = serde_json::to_string(trace_headers)?;
        MessageAttributeValue::builder()
            .data_type("String")
            .string_value(json)
            .build()
            .map_err(Into::into)
    };

    match attribute() {
        Ok(attr) => Some(attr),
        Err(err) => {
            tracing::debug!(
                name: "Sqs.Inject.DatadogAttributeBuildFailed",
                reason = %err,
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
        tracing::debug!(
            name: "Sqs.Inject.MessageAttributesFull",
            max_message_attributes = MAX_MESSAGE_ATTRIBUTES,
            action = "context injection skipped",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sqs::types::{
        ChangeMessageVisibilityBatchRequestEntry, DeleteMessageBatchRequestEntry,
        QueueAttributeName, SendMessageBatchRequestEntry,
    };
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    const TEST_TRACE_HEADER_KEY: &str = "test_context_injected";
    const TEST_QUEUE_URL: &str = "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue";

    fn test_trace_headers() -> HashMap<String, String> {
        HashMap::from([(TEST_TRACE_HEADER_KEY.to_string(), "true".to_string())])
    }

    fn inject_test_trace_headers(input: &mut Input) {
        inject_with_trace_headers(input, test_trace_headers);
    }

    fn parse_datadog_attribute(
        attrs: &HashMap<String, MessageAttributeValue>,
    ) -> HashMap<String, String> {
        let json_str = attrs[DATADOG_ATTRIBUTE_KEY].string_value().unwrap();
        serde_json::from_str(json_str).unwrap()
    }

    fn trace_context_propagator() -> TraceContextPropagator {
        TraceContextPropagator::new()
    }

    fn sns_envelope_body(data_type: &str, value: impl Into<serde_json::Value>) -> String {
        serde_json::json!({
            "Type": "Notification",
            "MessageId": "sns-message-id",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic",
            "Message": "hello",
            "MessageAttributes": {
                "_datadog": {
                    "Type": data_type,
                    "Value": value.into()
                }
            }
        })
        .to_string()
    }

    fn eventbridge_envelope_body(detail: impl Into<serde_json::Value>) -> String {
        serde_json::json!({
            "version": "0",
            "id": "event-id",
            "detail-type": "SampleMessage",
            "source": "rust-sqs-consumer-sample",
            "account": "123456789012",
            "time": "2026-08-04T00:00:00Z",
            "region": "us-east-1",
            "resources": [],
            "detail": detail.into()
        })
        .to_string()
    }

    fn assert_queue_url_extracted(input: Input) {
        assert_eq!(queue_url_from_input(&input), Some(TEST_QUEUE_URL));
    }

    #[test]
    fn extracts_queue_url_from_all_queue_scoped_inputs() {
        assert_queue_url_extracted(Input::erase(
            AddPermissionInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .label("test")
                .aws_account_ids("123456789012")
                .actions("SendMessage")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            ChangeMessageVisibilityInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .receipt_handle("handle")
                .visibility_timeout(30)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            ChangeMessageVisibilityBatchInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .entries(
                    ChangeMessageVisibilityBatchRequestEntry::builder()
                        .id("1")
                        .receipt_handle("handle")
                        .visibility_timeout(30)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            DeleteMessageInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .receipt_handle("handle")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            DeleteMessageBatchInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .entries(
                    DeleteMessageBatchRequestEntry::builder()
                        .id("1")
                        .receipt_handle("handle")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            DeleteQueueInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            GetQueueAttributesInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .attribute_names(QueueAttributeName::All)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            ListDeadLetterSourceQueuesInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            ListQueueTagsInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            PurgeQueueInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            ReceiveMessageInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            RemovePermissionInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .label("test")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            SendMessageInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .message_body("hello")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            SendMessageBatchInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .entries(
                    SendMessageBatchRequestEntry::builder()
                        .id("1")
                        .message_body("hello")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            SetQueueAttributesInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .attributes(QueueAttributeName::VisibilityTimeout, "30")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            TagQueueInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .tags("env", "test")
                .build()
                .unwrap(),
        ));
        assert_queue_url_extracted(Input::erase(
            UntagQueueInput::builder()
                .queue_url(TEST_QUEUE_URL)
                .tag_keys("env")
                .build()
                .unwrap(),
        ));
    }

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

        inject_test_trace_headers(&mut input);

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

        inject_test_trace_headers(&mut input);

        let input = input.downcast_ref::<SendMessageInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_datadog_attribute(attrs);
        assert_eq!(parsed[TEST_TRACE_HEADER_KEY], "true");
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

        inject_test_trace_headers(&mut input);

        let input = input.downcast_ref::<SendMessageBatchInput>().unwrap();
        let entries = input.entries.as_ref().unwrap();
        let attrs = entries[0].message_attributes.as_ref().unwrap();
        assert_eq!(attrs.len(), 10);
        let parsed = parse_datadog_attribute(attrs);
        assert_eq!(parsed[TEST_TRACE_HEADER_KEY], "true");
    }

    #[test]
    fn inject_dispatches_by_input_type() {
        let input = SendMessageInput::builder()
            .queue_url("https://example.com/test-queue")
            .message_body("test body")
            .build()
            .unwrap();
        let mut input = Input::erase(input);

        inject_test_trace_headers(&mut input);

        let input = input.downcast_ref::<SendMessageInput>().unwrap();
        let attrs = input.message_attributes.as_ref().unwrap();
        assert!(attrs.contains_key(DATADOG_ATTRIBUTE_KEY));
    }

    #[test]
    fn extract_context_reads_datadog_message_attribute() {
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
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_binary_datadog_message_attribute() {
        let datadog_attr = MessageAttributeValue::builder()
            .data_type("Binary")
            .binary_value(aws_smithy_types::Blob::new(
                serde_json::to_vec(&serde_json::json!({
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
                }))
                .unwrap(),
            ))
            .build()
            .unwrap();
        let message = Message::builder()
            .message_attributes(DATADOG_ATTRIBUTE_KEY, datadog_attr)
            .build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_sns_envelope_string_datadog_message_attribute() {
        let datadog_attr = serde_json::json!({
            "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
        })
        .to_string();
        let message = Message::builder()
            .body(sns_envelope_body("String", datadog_attr))
            .build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_sns_envelope_binary_datadog_message_attribute() {
        let datadog_attr = BASE64_STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
            }))
            .unwrap(),
        );
        let message = Message::builder()
            .body(sns_envelope_body("Binary", datadog_attr))
            .build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_eventbridge_detail_datadog_attribute_inside_sns_message() {
        let eventbridge_body = eventbridge_envelope_body(serde_json::json!({
            "message": "hello through eventbridge sns",
            "_datadog": {
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
            }
        }));
        let sns_body = serde_json::json!({
            "Type": "Notification",
            "MessageId": "sns-message-id",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic",
            "Message": eventbridge_body
        })
        .to_string();
        let message = Message::builder().body(sns_body).build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_eventbridge_detail_datadog_attribute() {
        let message = Message::builder()
            .body(eventbridge_envelope_body(serde_json::json!({
                "message": "hello",
                "_datadog": {
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
                }
            })))
            .build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_reads_eventbridge_detail_base64_datadog_attribute() {
        let datadog_attr = BASE64_STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
            }))
            .unwrap(),
        );
        let message = Message::builder()
            .body(eventbridge_envelope_body(serde_json::json!({
                "message": "hello through sns eventbridge pipe",
                "_datadog": datadog_attr
            })))
            .build();
        let propagator = trace_context_propagator();
        let extracted = extract_context_with_propagator(&message, &propagator).unwrap();

        assert!(extracted.span().span_context().is_valid());
    }

    #[test]
    fn extract_context_returns_none_for_eventbridge_detail_without_datadog_attribute() {
        let message = Message::builder()
            .body(eventbridge_envelope_body(serde_json::json!({
                "message": "hello"
            })))
            .build();
        let propagator = trace_context_propagator();

        assert!(extract_context_with_propagator(&message, &propagator).is_none());
    }

    #[test]
    fn extract_context_returns_none_for_unsupported_sns_envelope_datadog_attribute_type() {
        let datadog_attr = serde_json::json!({
            "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"
        })
        .to_string();
        let message = Message::builder()
            .body(sns_envelope_body("String.Array", datadog_attr))
            .build();
        let propagator = trace_context_propagator();

        assert!(extract_context_with_propagator(&message, &propagator).is_none());
    }

    #[test]
    fn extract_context_returns_none_with_invalid_trace_context() {
        let datadog_attr = MessageAttributeValue::builder()
            .data_type("String")
            .string_value(serde_json::json!({ "traceparent": "invalid" }).to_string())
            .build()
            .unwrap();
        let message = Message::builder()
            .message_attributes(DATADOG_ATTRIBUTE_KEY, datadog_attr)
            .build();

        let propagator = trace_context_propagator();
        assert!(extract_context_with_propagator(&message, &propagator).is_none());
    }

    #[test]
    fn extract_context_returns_none_without_datadog_message_attribute() {
        let message = Message::builder().build();

        let propagator = trace_context_propagator();
        assert!(extract_context_with_propagator(&message, &propagator).is_none());
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

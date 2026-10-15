// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Event inference ported from datadog-lambda-extension's Bottlecap.
//! Trigger parsers retain Bottlecap's event matching, metadata, and carrier extraction.
//! This adapter supplies span data to the OpenTelemetry lifecycle without extension services.

pub(crate) mod triggers;

use base64::{engine::general_purpose, DecodeError, Engine};
use datadog_opentelemetry::propagation::context::SpanContext;
use serde_json::Value;
use std::collections::HashMap;
use triggers::{
    event_bridge_event::EventBridgeEvent,
    sns_event::{SnsEntity, SnsRecord},
    sqs_event::extract_trace_context_from_aws_trace_header,
    IdentifiedTrigger, Trigger, FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG,
};

const MS_TO_NS: f64 = 1_000_000.0;
const S_TO_NS: f64 = 1_000_000_000.0;

/// The fields populated by Bottlecap's trigger parsers, independent of its protobuf span.
#[derive(Debug, Default, PartialEq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub(crate) struct SpanData {
    pub name: String,
    pub service: String,
    pub resource: String,
    pub r#type: String,
    pub start: i64,
    pub meta: HashMap<String, String>,
}

pub(crate) struct InferConfig {
    pub region: String,
    pub service_mapping: HashMap<String, String>,
    pub aws_service_representation_enabled: bool,
}

impl Default for InferConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            service_mapping: HashMap::new(),
            aws_service_representation_enabled: true,
        }
    }
}

#[derive(Default)]
pub(crate) struct InferenceResult {
    pub span_data: SpanData,
    pub is_async: bool,
    pub trigger_tags: HashMap<String, String>,
    pub carrier: HashMap<String, String>,
    pub generated_carrier: HashMap<String, String>,
    pub wrapped_span: Option<Box<InferenceResult>>,
}

impl InferenceResult {
    pub fn should_create_inferred_span(&self) -> bool {
        !self.span_data.name.is_empty()
    }
}

pub(crate) struct SpanInferrer {
    config: InferConfig,
}

impl SpanInferrer {
    pub fn new(config: InferConfig) -> Self {
        Self { config }
    }

    pub fn infer_span(&self, payload: &str) -> serde_json::Result<InferenceResult> {
        let payload: Value = serde_json::from_str(payload)?;
        let identified = IdentifiedTrigger::from_value(&payload);
        let Some(trigger) = identified.as_trigger() else {
            return Ok(InferenceResult::default());
        };
        let mut result = self.infer_trigger(trigger);
        result.generated_carrier = match &identified {
            IdentifiedTrigger::StepFunctionEvent(event) => {
                generated_carrier(event.get_span_context())
            }
            IdentifiedTrigger::SqsRecord(event) => extract_trace_context_from_aws_trace_header(
                event.attributes.aws_trace_header.clone(),
            )
            .map(generated_carrier)
            .unwrap_or_default(),
            _ => HashMap::new(),
        };
        result.wrapped_span = self.infer_wrapped_trigger(&identified).map(Box::new);
        if let Some(wrapped) = &result.wrapped_span {
            result.span_data.meta.extend(wrapped.trigger_tags.clone());
        }
        Ok(result)
    }

    fn infer_trigger(&self, trigger: &dyn Trigger) -> InferenceResult {
        let mut span_data = SpanData::default();
        // ALB and Step Functions intentionally leave span_data empty: they propagate
        // context and trigger tags but do not create an additional service span.
        trigger.enrich_span(
            &mut span_data,
            &self.config.service_mapping,
            self.config.aws_service_representation_enabled,
        );
        let is_async = trigger.is_async();
        if !span_data.name.is_empty() {
            span_data
                .meta
                .insert("_inferred_span.tag_source".into(), "self".into());
            span_data.meta.insert(
                "_inferred_span.synchronicity".into(),
                if is_async { "async" } else { "sync" }.into(),
            );
            if let Some(key) = trigger.get_dd_resource_key(&self.config.region) {
                span_data.meta.insert("dd_resource_key".into(), key);
            }
        }
        let mut trigger_tags = trigger.get_tags();
        trigger_tags.insert(
            FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG.into(),
            trigger.get_arn(&self.config.region),
        );
        InferenceResult {
            span_data,
            is_async,
            trigger_tags,
            carrier: trigger.get_carrier(),
            ..Default::default()
        }
    }

    fn infer_wrapped_trigger(&self, identified: &IdentifiedTrigger) -> Option<InferenceResult> {
        match identified {
            IdentifiedTrigger::SqsRecord(event) => {
                if let Ok(sns) = serde_json::from_str::<SnsEntity>(&event.body) {
                    return Some(self.infer_trigger(&SnsRecord {
                        sns,
                        event_subscription_arn: None,
                    }));
                }
                let event = serde_json::from_str::<EventBridgeEvent>(&event.body).ok()?;
                Some(self.infer_trigger(&event))
            }
            IdentifiedTrigger::SnsRecord(event) => {
                let event =
                    serde_json::from_str::<EventBridgeEvent>(event.sns.message.as_ref()?).ok()?;
                Some(self.infer_trigger(&event))
            }
            _ => None,
        }
    }
}

// Reuse the configured tracer propagator for generated context, including its sampling
// and origin metadata. Supply both formats so W3C-only configurations also work.
fn generated_carrier(context: SpanContext) -> HashMap<String, String> {
    let low = context.trace_id as u64;
    let high = context
        .tags
        .get("_dd.p.tid")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or((context.trace_id >> 64) as u64);
    let trace_id = (u128::from(high) << 64) | u128::from(low);
    let mut carrier = HashMap::from([
        ("x-datadog-trace-id".into(), low.to_string()),
        ("x-datadog-parent-id".into(), context.span_id.to_string()),
    ]);
    let mut state = Vec::new();
    if let Some(priority) = context.sampling.priority {
        let priority = priority.into_i8();
        carrier.insert("x-datadog-sampling-priority".into(), priority.to_string());
        state.push(format!("s:{priority}"));
    }
    if let Some(origin) = context.origin {
        state.push(format!("o:{origin}"));
        carrier.insert("x-datadog-origin".into(), origin);
    }
    if !context.tags.is_empty() {
        carrier.insert(
            "x-datadog-tags".into(),
            context
                .tags
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        state.extend(context.tags.iter().filter_map(|(key, value)| {
            key.strip_prefix("_dd.p.")
                .map(|key| format!("t.{key}:{value}"))
        }));
    }
    let sampled = u8::from(
        context
            .sampling
            .priority
            .is_some_and(|priority| priority.is_keep()),
    );
    carrier.insert(
        "traceparent".into(),
        format!("00-{trace_id:032x}-{:016x}-{sampled:02x}", context.span_id),
    );
    if !state.is_empty() {
        carrier.insert("tracestate".into(), format!("dd={}", state.join(";")));
    }
    carrier
}

fn get_aws_partition_by_region(region: &str) -> String {
    match region {
        r if r.starts_with("us-gov-") => "aws-us-gov".to_string(),
        r if r.starts_with("cn-") => "aws-cn".to_string(),
        _ => "aws".to_string(),
    }
}

fn base64_to_string(value: &str) -> Result<String, DecodeError> {
    general_purpose::STANDARD
        .decode(value)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn extract_propagation_tags(tags: &str) -> HashMap<String, String> {
    tags.split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            key.starts_with("_dd.p.")
                .then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Event inference ported from datadog-lambda-extension's Bottlecap.
//! Trigger parsers retain Bottlecap's event matching, metadata, and carrier extraction.
//! This adapter supplies span data to the OpenTelemetry lifecycle without extension services.

pub(crate) mod triggers;

use base64::{engine::general_purpose, DecodeError, Engine};
use datadog_opentelemetry::propagation::{
    context::SpanContext, datadog::DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY,
};
use serde_json::Value;
use std::collections::HashMap;
use triggers::{
    sqs_event::extract_trace_context_from_aws_trace_header, IdentifiedTrigger, Trigger,
    FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG,
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
    /// Name of the running function, used in Lambda function URL ARNs.
    pub function_name: String,
    pub service_mapping: HashMap<String, String>,
    pub aws_service_representation_enabled: bool,
}

impl Default for InferConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            function_name: String::new(),
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
    pub generated_context: Option<SpanContext>,
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
        let identified = IdentifiedTrigger::from_value(payload);
        let Some(trigger) = identified.as_trigger() else {
            return Ok(InferenceResult::default());
        };
        let mut result = self.infer_trigger(trigger);
        result.generated_context = match &identified {
            IdentifiedTrigger::StepFunctionEvent(event) => {
                Some(generated_context(event.get_span_context()))
            }
            IdentifiedTrigger::SqsRecord(event) => extract_trace_context_from_aws_trace_header(
                event.attributes.aws_trace_header.as_deref(),
            )
            .map(generated_context),
            _ => None,
        };
        result.wrapped_span = self.infer_wrapped_trigger(&identified).map(Box::new);
        if let Some(wrapped) = &result.wrapped_span {
            // Bottlecap merges the wrapped trigger's tags before enriching the inner span,
            // so inner span tags take precedence. The wrapped event source ARN is not merged.
            wrapped
                .trigger_tags
                .iter()
                .filter(|(key, _)| key.as_str() != FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG)
                .for_each(|(key, value)| {
                    result
                        .span_data
                        .meta
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                });
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
            trigger.get_arn(&self.config.region, &self.config.function_name),
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
            IdentifiedTrigger::SqsRecord(event) => event
                .wrapped_event()
                .map(|wrapped| self.infer_trigger(wrapped.as_trigger())),
            IdentifiedTrigger::SnsRecord(event) => event
                .wrapped_event()
                .map(|wrapped| self.infer_trigger(wrapped)),
            _ => None,
        }
    }
}

// Bottlecap represents Step Functions' high trace bits in propagation tags.
// Reconstitute the full ID before passing the context directly to the tracer.
fn generated_context(mut context: SpanContext) -> SpanContext {
    if let Some(high) = context
        .tags
        .get(DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY)
        .and_then(|value| u64::from_str_radix(value, 16).ok())
    {
        context.trace_id = (u128::from(high) << 64) | u128::from(context.trace_id as u64);
    }
    context.is_remote = true;
    context
}

/// Derives the AWS partition from a region, matching `datadog-aws-core`.
///
/// `us-isof-` and `us-isob-` must be checked before the shorter `us-iso-` prefix.
fn get_aws_partition_by_region(region: &str) -> &'static str {
    [
        ("cn-", "aws-cn"),
        ("us-gov-", "aws-us-gov"),
        ("us-isof-", "aws-iso-f"),
        ("us-isob-", "aws-iso-b"),
        ("us-iso-", "aws-iso"),
        ("eu-isoe-", "aws-iso-e"),
        ("eusc-", "aws-eusc"),
    ]
    .into_iter()
    .find_map(|(prefix, partition)| region.starts_with(prefix).then_some(partition))
    .unwrap_or("aws")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;

    fn infer_fixture(name: &str) -> InferenceResult {
        SpanInferrer::new(InferConfig {
            region: "us-east-1".into(),
            ..InferConfig::default()
        })
        .infer_span(&read_json_file(name))
        .unwrap()
    }

    #[test]
    fn partition_matches_aws_partition_prefixes() {
        for (region, partition) in [
            ("us-east-1", "aws"),
            ("cn-north-1", "aws-cn"),
            ("us-gov-west-1", "aws-us-gov"),
            ("us-iso-east-1", "aws-iso"),
            ("us-isob-east-1", "aws-iso-b"),
            ("eu-isoe-west-1", "aws-iso-e"),
            ("us-isof-south-1", "aws-iso-f"),
            ("eusc-de-east-1", "aws-eusc"),
            ("unknown-region-1", "aws"),
        ] {
            assert_eq!(get_aws_partition_by_region(region), partition, "{region}");
        }
    }

    #[test]
    fn iso_region_arns_use_the_iso_partition() {
        let result = SpanInferrer::new(InferConfig {
            region: "us-iso-east-1".into(),
            ..InferConfig::default()
        })
        .infer_span(&read_json_file("sqs_event.json"))
        .unwrap();
        assert!(
            result.trigger_tags[FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG]
                .starts_with("arn:aws-iso:sqs:us-iso-east-1:"),
            "{}",
            result.trigger_tags[FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG]
        );
    }

    #[test]
    fn wrapped_trigger_tags_exclude_the_wrapped_event_source_arn() {
        for (fixture, wrapped_source) in [
            ("sns_sqs_event.json", "sns"),
            ("eventbridge_sqs_event.json", "eventbridge"),
            ("eventbridge_sns_event.json", "eventbridge"),
        ] {
            let result = infer_fixture(fixture);
            let meta = &result.span_data.meta;
            assert_eq!(
                meta.get(triggers::FUNCTION_TRIGGER_EVENT_SOURCE_TAG)
                    .map(String::as_str),
                Some(wrapped_source),
                "{fixture}"
            );
            assert!(
                !meta.contains_key(FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG),
                "{fixture}"
            );
            // The invocation span still reports the outermost trigger's own ARN.
            assert!(
                result
                    .trigger_tags
                    .contains_key(FUNCTION_TRIGGER_EVENT_SOURCE_ARN_TAG),
                "{fixture}"
            );
        }
    }
}

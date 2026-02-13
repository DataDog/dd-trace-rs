// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::sync::RwLock;

use crate::mappings::{
    get_dd_key_for_otlp_attribute, get_otel_env, get_otel_operation_name_v2, get_otel_resource_v2,
    get_otel_service, get_otel_status_code, AttributeIndices, AttributeKey, OtelSpan,
};
use crate::sampling::{SamplingData, SpanProperties};
use opentelemetry::{Key, KeyValue};

pub struct PreSampledSpan<'a> {
    pub name: &'a str,
    pub span_kind: opentelemetry::trace::SpanKind,
    pub attributes: &'a [opentelemetry::KeyValue],
    pub resource: &'a opentelemetry_sdk::Resource,
    pub span_attrs: AttributeIndices,
}

impl<'a> PreSampledSpan<'a> {
    pub fn new(
        name: &'a str,
        span_kind: opentelemetry::trace::SpanKind,
        attributes: &'a [opentelemetry::KeyValue],
        resource: &'a opentelemetry_sdk::Resource,
    ) -> Self {
        Self {
            name,
            span_kind,
            attributes,
            resource,
            span_attrs: AttributeIndices::from_attribute_slice(attributes),
        }
    }
}

impl<'a> OtelSpan<'a> for PreSampledSpan<'a> {
    fn name(&self) -> &'a str {
        self.name
    }

    fn span_kind(&self) -> opentelemetry::trace::SpanKind {
        self.span_kind.clone()
    }

    fn has_attr(&self, attr_key: AttributeKey) -> bool {
        self.span_attrs.get(attr_key).is_some()
    }

    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.attributes.get(idx)?;
        Some(Cow::Owned(kv.value.to_string()))
    }

    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.attributes.get(idx)?;
        let i = match kv.value {
            opentelemetry::Value::I64(i) => i,
            opentelemetry::Value::F64(i) if i == i.floor() && i < i64::MAX as f64 => i as i64,
            _ => return None,
        };
        T::try_from(i).ok()
    }

    fn attr_len(&self) -> usize {
        self.attributes.len()
    }

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<opentelemetry::Value> {
        self.resource.get(&Key::from_static_str(attr_key.key()))
    }

    fn res_len(&self) -> usize {
        self.resource.len()
    }
}

impl SpanProperties for PreSampledSpan<'_> {
    type Attribute = opentelemetry::KeyValue;
    type AttributesIter<'b>
        = std::slice::Iter<'b, opentelemetry::KeyValue>
    where
        Self: 'b;

    fn operation_name(&self) -> Cow<'_, str> {
        get_otel_operation_name_v2(self)
    }

    fn service(&self) -> Cow<'_, str> {
        get_otel_service(self)
    }

    fn env(&self) -> Cow<'_, str> {
        get_otel_env(self)
    }

    fn resource(&self) -> Cow<'_, str> {
        get_otel_resource_v2(self)
    }

    fn status_code(&self) -> Option<u32> {
        get_otel_status_code(self)
    }

    fn attributes(&self) -> Self::AttributesIter<'_> {
        self.attributes.iter()
    }

    fn get_alternate_key<'b>(&self, key: &'b str) -> Option<Cow<'b, str>> {
        let mapped = get_dd_key_for_otlp_attribute(key);
        // If the mapping returned an empty string or the same key, there's no alternate
        if mapped.is_empty() || mapped.as_ref() == key {
            None
        } else {
            Some(mapped)
        }
    }
}

/// OpenTelemetry Sampling Data implementation.
///
/// Provides the necessary data for making sampling decisions on OpenTelemetry spans.
/// This struct contains references to span metadata including the trace ID, span name,
/// span kind, attributes, and resource information.
pub struct OtelSamplingData<'a> {
    is_parent_sampled: Option<bool>,
    trace_id: &'a opentelemetry::trace::TraceId,
    name: &'a str,
    span_kind: opentelemetry::trace::SpanKind,
    attributes: &'a [KeyValue],
    resource: &'a RwLock<opentelemetry_sdk::Resource>,
}

impl<'a> OtelSamplingData<'a> {
    /// Creates a new OpenTelemetry sampling data instance.
    ///
    /// # Arguments
    ///
    /// * `is_parent_sampled` - Whether the parent span was sampled, if known
    /// * `trace_id` - The trace ID for this span
    /// * `name` - The span name
    /// * `span_kind` - The kind of span (e.g., Server, Client)
    /// * `attributes` - The span's attributes
    /// * `resource` - The OpenTelemetry resource containing service metadata
    pub fn new(
        is_parent_sampled: Option<bool>,
        trace_id: &'a opentelemetry::trace::TraceId,
        name: &'a str,
        span_kind: opentelemetry::trace::SpanKind,
        attributes: &'a [KeyValue],
        resource: &'a RwLock<opentelemetry_sdk::Resource>,
    ) -> Self {
        Self {
            is_parent_sampled,
            trace_id,
            name,
            span_kind,
            attributes,
            resource,
        }
    }
}

impl SamplingData for OtelSamplingData<'_> {
    type TraceId = opentelemetry::trace::TraceId;
    type Properties<'b>
        = PreSampledSpan<'b>
    where
        Self: 'b;

    fn is_parent_sampled(&self) -> Option<bool> {
        self.is_parent_sampled
    }
    fn trace_id(&self) -> &Self::TraceId {
        self.trace_id
    }

    fn with_span_properties<S, T, F>(&self, s: &S, f: F) -> T
    where
        F: for<'b> Fn(&S, &PreSampledSpan<'b>) -> T,
    {
        let resource_guard = self.resource.read().unwrap();
        let span = PreSampledSpan::new(
            self.name,
            self.span_kind.clone(),
            self.attributes,
            &resource_guard,
        );
        f(s, &span)
    }
}

impl crate::sampling::TraceIdLike for opentelemetry::trace::TraceId {
    type Item = opentelemetry::trace::TraceId;

    fn to_u128(&self) -> u128 {
        u128::from_be_bytes(self.to_bytes())
    }

    fn inner(&self) -> &Self::Item {
        self
    }
}

/// Factory for creating OpenTelemetry KeyValue attributes.
pub struct OtelAttributeFactory;

impl crate::sampling::AttributeFactory for OtelAttributeFactory {
    type Attribute = opentelemetry::KeyValue;

    fn create_i64(&self, key: &'static str, value: i64) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }

    fn create_f64(&self, key: &'static str, value: f64) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }

    fn create_string(&self, key: &'static str, value: Cow<'static, str>) -> Self::Attribute {
        opentelemetry::KeyValue::new(key, value)
    }
}

/// Converts a Datadog sampling priority to an OpenTelemetry sampling decision.
///
/// # Arguments
///
/// * `priority` - The Datadog sampling priority
///
/// # Returns
///
/// The corresponding OpenTelemetry sampling decision:
/// - `RecordAndSample` if the priority indicates the trace should be kept
/// - `RecordOnly` if the priority indicates the trace should be dropped
pub(crate) fn priority_to_otel_decision(
    priority: crate::core::sampling::SamplingPriority,
) -> opentelemetry::trace::SamplingDecision {
    if priority.is_keep() {
        opentelemetry::trace::SamplingDecision::RecordAndSample
    } else {
        opentelemetry::trace::SamplingDecision::RecordOnly
    }
}

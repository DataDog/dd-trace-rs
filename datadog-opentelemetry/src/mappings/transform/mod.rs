// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Transform
//!
//! This code has been ported from the otlp receiver in the datadog agent.
//!
//! # Source
//!
//! This should be a 1:1 port of this commit
//! https://github.com/DataDog/datadog-agent/blob/97e6db0d4130c8545ede77111a2590eb034c2f11/pkg/trace/transform/transform.go
//!
//! It performs a mapping between otel span data and datadog spans. The conversion is done using the
//! default configuration of the datadog agent, thus compared to the original code, we have removed
//! the following features:
//! * V1 conversion. The otlp receiver has a v1 and v2 conversion. We only support v2 because we
//!   don't need backward compatibility.
//! * The `ignore_missing_datadog_fields=true` option. This is false by default in the agent anyway
//!
//! # Datastructures
//!
//! The original otlp receiver does OTLP -> agent span struct conversion.
//! Compared to it, we do Otel Span Data -> trace exporter span struct conversion.
//!
//! Code in otel_util.rs is generic over the otel span model, but the code manipulating
//! the datadog span struct is not.
//!
//! # Attribute extraction
//!
//! Compared to the original code, we read attributes from span a bit differently.
//! The go code loops through all attributes everytime it is looking for a specific one.
//! The code in attribute_keys.rs loops only once and then stores the offsets at which the
//! attributes are stored, for the set of keys we are interested in.  

pub mod attribute_keys;
pub mod otel_util;
pub mod semconv_shim;

#[cfg(feature = "test-utils")]
pub mod transform_tests;

use attribute_keys::*;
use otel_util::*;

use std::{
    borrow::{Borrow, Cow},
    collections::{hash_map, HashMap},
};

use datadog_trace_utils::span::SpanText;
use opentelemetry::{
    trace::{Link, SpanKind},
    Key, KeyValue, Value,
};
use opentelemetry_sdk::Resource;
pub use opentelemetry_semantic_conventions as semconv;

use crate::core::constants::SAMPLING_RATE_EVENT_EXTRACTION_KEY;

use super::sdk_span::SdkSpan;

pub type SpanStr<'a> = CowStr<'a>;
pub type DdSpan<'a> = datadog_trace_utils::span::Span<CowStr<'a>>;
type DdSpanEvent<'a> = datadog_trace_utils::span::SpanEvent<CowStr<'a>>;
type DdSpanLink<'a> = datadog_trace_utils::span::SpanLink<CowStr<'a>>;
type DdAnyValue<'a> = datadog_trace_utils::span::AttributeAnyValue<CowStr<'a>>;
type DdAttributeAnyValue<'a> = datadog_trace_utils::span::AttributeAnyValue<CowStr<'a>>;
type DdAttributeArrayValue<'a> = datadog_trace_utils::span::AttributeArrayValue<CowStr<'a>>;
type DdScalarValue<'a> = datadog_trace_utils::span::AttributeArrayValue<CowStr<'a>>;

fn set_meta_otlp<'a>(k: SpanStr<'a>, v: SpanStr<'a>, dd_span: &mut DdSpan<'a>) {
    match k.borrow() {
        "operation.name" => dd_span.name = v,
        "service.name" => dd_span.service = v,
        "resource.name" => dd_span.resource = v,
        "span.type" => dd_span.r#type = v,
        "analytics.event" => {
            if let Ok(parsed) = v.as_str().to_lowercase().parse::<bool>() {
                dd_span.metrics.insert(
                    SpanStr::from_static_str(SAMPLING_RATE_EVENT_EXTRACTION_KEY),
                    if parsed { 1.0 } else { 0.0 },
                );
            }
        }
        _ => {
            dd_span.meta.insert(k, v);
        }
    }
}

fn set_meta_otlp_with_semconv_mappings<'a>(
    k: &'a str,
    value: &'a opentelemetry::Value,
    dd_span: &mut DdSpan<'a>,
) {
    let mapped_key = get_dd_key_for_otlp_attribute(k);
    if mapped_key.is_empty() {
        return;
    }
    let mapped_key = SpanStr::from_cow(mapped_key);
    if is_meta_key(mapped_key.as_str())
        && !dd_span
            .meta
            .get(&mapped_key)
            .map(|v| v.as_str().is_empty())
            .unwrap_or(true)
    {
        return;
    }
    set_meta_otlp(
        mapped_key,
        SpanStr::from_cow(otel_value_string_repr(value)),
        dd_span,
    );
}

fn set_metric_otlp<'a>(s: &mut DdSpan<'a>, k: SpanStr<'a>, v: f64) {
    match k.as_str() {
        "sampling.priority" => {
            s.metrics
                .insert(SpanStr::from_static_str("_sampling_priority_v1"), v);
        }
        _ => {
            s.metrics.insert(k, v);
        }
    }
}

fn set_metric_otlp_with_semconv_mappings<'a>(k: &'a str, value: f64, dd_span: &mut DdSpan<'a>) {
    let mapped_key = get_dd_key_for_otlp_attribute(k);
    let mapped_key = SpanStr::from_cow(mapped_key);

    if !mapped_key.as_str().is_empty() {
        if is_meta_key(mapped_key.as_str()) && dd_span.metrics.contains_key(&mapped_key) {
            return;
        }
        set_metric_otlp(dd_span, mapped_key, value);
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L69
fn otel_span_to_dd_span_minimal<'a>(
    span: &SpanExtractArgs<'a, '_>,
    is_top_level: bool,
) -> DdSpan<'a> {
    let (trace_id_lower_half, _) = otel_trace_id_to_dd_id(span.span.span_context.trace_id());
    let span_id = otel_span_id_to_dd_id(span.span.span_context.span_id());
    let parent_id = otel_span_id_to_dd_id(span.span.parent_span_id);
    let start = time_as_unix_nanos(span.span.start_time);
    let end = time_as_unix_nanos(span.span.end_time);
    // duration should not be negative
    let duration = end.checked_sub(start).unwrap_or(0).max(0);

    let mut dd_span = DdSpan {
        service: SpanStr::from_cow(span.get_attr_str(DATADOG_SERVICE)),
        name: SpanStr::from_cow(span.get_attr_str(DATADOG_NAME)),
        resource: SpanStr::from_cow(span.get_attr_str(DATADOG_RESOURCE)),
        r#type: SpanStr::from_cow(span.get_attr_str(DATADOG_TYPE)),
        trace_id: trace_id_lower_half.into(),
        span_id,
        parent_id,
        start,
        duration,
        meta: HashMap::with_capacity(span.attr_len() + span.res_len()),
        // We will likely put _sampling_priority, maybe _dd.measured, top level
        // And by default tracing tags by code.line.number, thread.id and busy_ns/idle_ns
        //
        // Why 6? This seems like a good number to prevent small reallocations while not
        // using too much memory
        metrics: HashMap::with_capacity(6),
        ..Default::default()
    };
    if let Some(error) = span.get_attr_num(DATADOG_ERROR) {
        dd_span.error = error;
    } else if matches!(span.span.status, opentelemetry::trace::Status::Error { .. }) {
        dd_span.error = 1;
    }

    if let Some(span_kind) = span.get_attr_str_opt(DATADOG_SPAN_KIND) {
        dd_span.meta.insert(
            SpanStr::from_static_str("span.kind"),
            SpanStr::from_cow(span_kind),
        );
    } else {
        let span_kind_str: &'static str = match span.span_kind() {
            SpanKind::Client => "client",
            SpanKind::Server => "server",
            SpanKind::Producer => "producer",
            SpanKind::Consumer => "consumer",
            SpanKind::Internal => "internal",
        };
        dd_span.meta.insert(
            SpanStr::from_static_str("span.kind"),
            SpanStr::from_static_str(span_kind_str),
        );
    }

    if dd_span.service.as_str().is_empty() {
        dd_span.service = SpanStr::from_cow(get_otel_service(span));
    }

    if dd_span.name.as_str().is_empty() {
        dd_span.name = SpanStr::from_cow(get_otel_operation_name_v2(span));
    }

    if dd_span.resource.as_str().is_empty() {
        dd_span.resource = SpanStr::from_cow(get_otel_resource_v2(span));
    }
    if dd_span.r#type.as_str().is_empty() {
        dd_span.r#type = SpanStr::from_cow(get_otel_span_type(span));
    }
    let code: u32 = if let Some(http_status_code) = span.get_attr_num(DATADOG_HTTP_STATUS_CODE) {
        http_status_code
    } else {
        get_otel_status_code(span)
    };
    if code != 0 {
        dd_span.meta.insert(
            SpanStr::from_static_str("http.status_code"),
            SpanStr::from_string(code.to_string()),
        );
    }

    if is_top_level {
        dd_span
            .metrics
            .insert(SpanStr::from_static_str("_top_level"), 1.0);
    }
    if span.get_attr_num(DD_MEASURED) == Some(1)
        || matches!(span.span_kind(), SpanKind::Client | SpanKind::Producer)
    {
        dd_span
            .metrics
            .insert(SpanStr::from_static_str("_dd.measured"), 1.0);
    }
    // TODO(paullgdc):
    // The go code does the following thing, because the affect stats computation
    // * sets peer tags
    //
    // In our case, this is hard because tags need to be fetched from the agent /info endpoint

    dd_span
}

fn otel_span_id_to_dd_id(span_id: opentelemetry::SpanId) -> u64 {
    u64::from_be_bytes(span_id.to_bytes())
}

// Returns (low, high)
fn otel_trace_id_to_dd_id(trace_id: opentelemetry::TraceId) -> (u64, u64) {
    let trace_id: [u8; 16] = trace_id.to_bytes();
    // Unwrap ok, we take the lower 8 bytes and upper 8 bytes of a 16 byte array
    let lower_half = u64::from_be_bytes(trace_id[8..16].try_into().unwrap());
    let upper_half = u64::from_be_bytes(trace_id[0..8].try_into().unwrap());
    (lower_half, upper_half)
}

fn time_as_unix_nanos(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L495
fn status_to_error(status: &opentelemetry::trace::Status, dd_span: &mut DdSpan) -> i32 {
    if !matches!(status, opentelemetry::trace::Status::Error { .. }) {
        return 0;
    }
    for e in &dd_span.span_events {
        if !e.name.as_str().eq_ignore_ascii_case("exception") {
            continue;
        }
        for (otel_key, dd_key) in [
            (semconv::attribute::EXCEPTION_MESSAGE, "error.message"),
            (semconv::attribute::EXCEPTION_TYPE, "error.type"),
            (semconv::attribute::EXCEPTION_STACKTRACE, "error.stack"),
        ] {
            if let Some(attr) = e.attributes.get(&SpanStr::from_static_str(otel_key)) {
                dd_span
                    .meta
                    .insert(SpanStr::from_static_str(dd_key), dd_value_to_string(attr));
            }
        }
    }
    let error_msg_key = SpanStr::from_static_str("error.message");
    if let hash_map::Entry::Vacant(error_msg_slot) = dd_span.meta.entry(error_msg_key.clone()) {
        match status {
            opentelemetry::trace::Status::Error { description, .. } if !description.is_empty() => {
                error_msg_slot.insert(SpanStr::from_cow(description.clone()));
            }
            _ => {
                for key in ["http.response.status_code", "http.status_code"] {
                    let Some(code) = dd_span.meta.get(&SpanStr::from_static_str(key)) else {
                        continue;
                    };
                    if let Some(http_text) = dd_span
                        .meta
                        .get(&SpanStr::from_static_str("http.status_text"))
                    {
                        dd_span.meta.insert(
                            error_msg_key,
                            SpanStr::from_string(format!(
                                "{} {}",
                                code.as_str(),
                                http_text.as_str()
                            )),
                        );
                    } else {
                        dd_span.meta.insert(error_msg_key, code.clone());
                    }
                    break;
                }
            }
        }
    }

    1
}

/// https://github.com/DataDog/datadog-agent/blob/a4dea246effb49f2781b451a5b60aa2524fbef75/pkg/trace/transform/transform.go#L328
fn tag_span_if_contains_exception(dd_span: &mut DdSpan) {
    if dd_span
        .span_events
        .iter()
        .any(|e| e.name.as_str().eq_ignore_ascii_case("exception"))
    {
        dd_span.meta.insert(
            SpanStr::from_static_str("_dd.span_events.has_exception"),
            SpanStr::from_static_str("true"),
        );
    }
}

fn otel_value_to_dd_scalar(value: &opentelemetry::Value) -> DdAttributeAnyValue<'_> {
    fn map_vec<'a, T: 'a>(
        v: impl IntoIterator<Item = T>,
        constructor: fn(T) -> DdScalarValue<'a>,
    ) -> DdAnyValue<'a> {
        DdAnyValue::Array(v.into_iter().map(constructor).collect::<Vec<_>>())
    }
    match value {
        opentelemetry::Value::I64(i) => DdAnyValue::SingleValue(DdScalarValue::Integer(*i)),
        opentelemetry::Value::F64(f) => DdAnyValue::SingleValue(DdScalarValue::Double(*f)),
        opentelemetry::Value::Bool(b) => DdAnyValue::SingleValue(DdScalarValue::Boolean(*b)),
        opentelemetry::Value::Array(opentelemetry::Array::Bool(v)) => {
            map_vec(v.iter().copied(), DdScalarValue::Boolean)
        }
        opentelemetry::Value::Array(opentelemetry::Array::I64(v)) => {
            map_vec(v.iter().copied(), DdScalarValue::Integer)
        }
        opentelemetry::Value::Array(opentelemetry::Array::F64(v)) => {
            map_vec(v.iter().copied(), DdScalarValue::Double)
        }
        opentelemetry::Value::Array(opentelemetry::Array::String(v)) => map_vec(
            v.iter().map(|s| SpanStr::from_str(s.as_str())),
            DdScalarValue::String,
        ),
        _ => DdAnyValue::SingleValue(DdScalarValue::String(SpanStr::from_cow(
            otel_value_string_repr(value),
        ))),
    }
}

fn dd_value_to_string<'a>(value: &DdAttributeAnyValue<'a>) -> SpanStr<'a> {
    use std::fmt::Write;
    fn write_scalar(value: &DdAttributeArrayValue, w: &mut String) {
        let _ = match value {
            DdAttributeArrayValue::String(s) => write!(w, "{}", s.as_str()),
            DdAttributeArrayValue::Integer(i) => write!(w, "{i}"),
            DdAttributeArrayValue::Double(d) => write!(w, "{d}"),
            DdAttributeArrayValue::Boolean(b) => write!(w, "{b}"),
        };
    }
    fn write_vec(value: &[DdAttributeArrayValue], w: &mut String) {
        w.push('[');
        for (i, v) in value.iter().enumerate() {
            if i != 0 {
                w.push(',');
            }
            write_scalar(v, w);
        }
        w.push(']');
    }
    match value {
        DdAttributeAnyValue::SingleValue(DdAttributeArrayValue::String(s)) => s.clone(),
        DdAttributeAnyValue::SingleValue(attribute_array_value) => {
            let mut w = String::new();
            write_scalar(attribute_array_value, &mut w);
            SpanStr::from_string(w)
        }
        DdAttributeAnyValue::Array(attribute_array_values) => {
            let mut w = String::new();
            write_vec(attribute_array_values, &mut w);
            SpanStr::from_string(w)
        }
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L217
const DD_SEMANTICS_KEY_TO_META_KEY: &[(AttributeKey, &str)] = &[
    (DATADOG_ENV, "env"),
    (DATADOG_VERSION, "version"),
    (DATADOG_HTTP_STATUS_CODE, "http.status_code"),
    (DATADOG_ERROR_MSG, "error.message"),
    (DATADOG_ERROR_TYPE, "error.type"),
    (DATADOG_ERROR_STACK, "error.stack"),
];

/// Checks that the key is in the list of dd keys mapped from meta keys
fn is_meta_key(key: &str) -> bool {
    matches!(
        key,
        "env" | "version" | "http.status_code" | "error.message" | "error.type" | "error.stack"
    )
}

struct SpanExtractArgs<'a, 'b> {
    span: &'b SdkSpan<'a>,
    resource: &'a Resource,
    span_attrs: AttributeIndices,
}

impl<'a, 'b> SpanExtractArgs<'a, 'b> {
    pub fn new(span: &'b SdkSpan<'a>, resource: &'a Resource) -> Self {
        let span_attrs = AttributeIndices::from_attribute_slice(span.attributes);
        Self {
            span,
            span_attrs,
            resource,
        }
    }
}

impl<'a> OtelSpan<'a> for SpanExtractArgs<'a, '_> {
    fn name(&self) -> &'a str {
        self.span.name
    }

    fn span_kind(&self) -> SpanKind {
        self.span.span_kind.clone()
    }

    fn has_attr(&self, attr_key: AttributeKey) -> bool {
        self.span_attrs.get(attr_key).is_some()
    }

    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'a, str>> {
        let idx = self.span_attrs.get(attr_key)?;
        let v = &self.span.attributes.get(idx)?.value;
        Some(otel_value_string_repr(v))
    }

    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.span.attributes.get(idx)?;
        let i = match kv.value {
            opentelemetry::Value::I64(i) => i,
            opentelemetry::Value::F64(i) if i == i.floor() && i < i64::MAX as f64 => i as i64,
            _ => return None,
        };
        T::try_from(i).ok()
    }

    fn attr_len(&self) -> usize {
        self.span.attributes.len()
    }

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<Value> {
        self.resource.get(&Key::from_static_str(attr_key.key()))
    }

    fn res_len(&self) -> usize {
        self.resource.len()
    }
}

pub fn otel_value_string_repr(v: &Value) -> Cow<'_, str> {
    match v {
        Value::Bool(true) => Cow::Borrowed("true"),
        Value::Bool(false) => Cow::Borrowed("false"),
        Value::I64(0) => Cow::Borrowed("0"),
        Value::I64(1) => Cow::Borrowed("1"),
        Value::I64(i) => Cow::Owned(i.to_string()),
        Value::F64(0.0) => Cow::Borrowed("0"),
        Value::F64(1.0) => Cow::Borrowed("1"),
        Value::F64(i) => Cow::Owned(i.to_string()),
        Value::String(string_value) => Cow::Borrowed(string_value.as_str()),
        Value::Array(a) => Cow::Owned(a.to_string()),
        _ => Cow::Owned(v.to_string()),
    }
}

#[derive(Clone, Default, PartialEq, Eq, Hash, serde::Serialize, Debug)]
pub struct CowStr<'a>(Cow<'a, str>);

impl<'a> CowStr<'a> {
    fn from_cow(c: Cow<'a, str>) -> Self {
        Self(c)
    }

    pub fn from_string(s: String) -> Self {
        Self(Cow::Owned(s))
    }

    pub fn from_str(s: &'a str) -> Self {
        Self(Cow::Borrowed(s))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl std::borrow::Borrow<str> for CowStr<'_> {
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}

impl SpanText for CowStr<'_> {
    fn from_static_str(value: &'static str) -> Self {
        CowStr(Cow::Borrowed(value))
    }
}

/// Converts an OpenTelemetry span to a Datadog span.
/// https://github.com/DataDog/datadog-agent/blob/d91c1b47da4f5f24559f49be284e547cc847d5e2/pkg/trace/transform/transform.go#L236
///
/// Here are the main differences with the original code:
/// * No tag normalization
///
/// And we don't implement the following feature flags, and instead use the default paths:
/// * `enable_otlp_compute_top_level_by_span_kind` => default to true
/// * `IgnoreMissingDatadogFields` => default to false
/// * `disable_operation_and_resource_name_logic_v2` => default to false
pub fn otel_span_to_dd_span<'a>(
    otel_span: &SdkSpan<'a>,
    otel_resource: &'a Resource,
) -> DdSpan<'a> {
    // There is a performance optimization possible here:
    // The otlp receiver splits span conversion into two steps
    // 1. The minimal fields used by Stats computation
    // 2. The rest of the fields
    //
    // If we use CSS we could probably do only 1. if we know the span is going to be dropped before
    // being sent...

    let span_extracted = SpanExtractArgs::new(otel_span, otel_resource);

    // Top level spans are computed later
    let is_top_level = false;
    let mut dd_span = otel_span_to_dd_span_minimal(&span_extracted, is_top_level);

    for (dd_semantics_key, meta_key) in DD_SEMANTICS_KEY_TO_META_KEY {
        let value = span_extracted.get_attr_str(*dd_semantics_key);
        if !value.is_empty() {
            dd_span
                .meta
                .insert(SpanStr::from_static_str(meta_key), SpanStr::from_cow(value));
        }
    }

    for (key, value) in otel_resource.iter() {
        set_meta_otlp_with_semconv_mappings(key.as_str(), value, &mut dd_span);
    }

    for opentelemetry::KeyValue { key, value, .. } in otel_span.instrumentation_scope.attributes() {
        let key = SpanStr::from_string(key.to_string());
        let value = SpanStr::from_string(value.to_string());
        dd_span.meta.insert(key, value);
    }
    let otel_trace_id = format!(
        "{:032x}",
        u128::from_be_bytes(otel_span.span_context.trace_id().to_bytes())
    );
    dd_span.meta.insert(
        SpanStr::from_static_str("otel.trace_id"),
        SpanStr::from_string(otel_trace_id),
    );

    if let hash_map::Entry::Vacant(version_slot) =
        dd_span.meta.entry(SpanStr::from_static_str("version"))
    {
        let version = otel_resource
            .get(&Key::from_static_str(SERVICE_VERSION.key()))
            .map(|v| v.to_string())
            .unwrap_or_default();
        if !version.is_empty() {
            version_slot.insert(SpanStr::from_string(version));
        }
    }

    for KeyValue { key, value, .. } in otel_span.attributes {
        let key = key.as_str();
        if key.starts_with("datadog.") {
            continue;
        }
        match value {
            opentelemetry::Value::I64(v) => {
                set_metric_otlp_with_semconv_mappings(key, *v as f64, &mut dd_span);
            }
            opentelemetry::Value::F64(v) => {
                set_metric_otlp_with_semconv_mappings(key, *v, &mut dd_span);
            }
            _ => {
                set_meta_otlp_with_semconv_mappings(key, value, &mut dd_span);
            }
        }
    }

    if let hash_map::Entry::Vacant(env_slot) = dd_span.meta.entry(SpanStr::from_static_str("env")) {
        let env = get_otel_env(&span_extracted);
        if !env.is_empty() {
            env_slot.insert(SpanStr::from_cow(env));
        }
    }

    dd_span.span_links = otel_span
        .links
        .iter()
        .map(
            |Link {
                 span_context,
                 attributes: otel_attributes,
                 ..
             }| {
                let (trace_id, trace_id_high) = otel_trace_id_to_dd_id(span_context.trace_id());
                let span_id = otel_span_id_to_dd_id(span_context.span_id());
                let tracestate = SpanStr::from_string(span_context.trace_state().header());
                let flags = span_context.trace_flags().to_u8() as u32;
                let attributes = otel_attributes
                    .iter()
                    .map(|KeyValue { key, value, .. }| {
                        let key = SpanStr::from_str(key.as_str());
                        let value = SpanStr::from_cow(otel_value_string_repr(value));
                        (key, value)
                    })
                    .collect();
                DdSpanLink {
                    trace_id,
                    trace_id_high,
                    span_id,
                    attributes,
                    tracestate,
                    flags,
                }
            },
        )
        .collect();
    dd_span.span_events = otel_span
        .events
        .iter()
        .map(|e| {
            let time_unix_nano = time_as_unix_nanos(e.timestamp).max(0) as u64;
            let name = SpanStr::from_string(e.name.to_string());
            let attributes = e
                .attributes
                .iter()
                .map(|KeyValue { key, value, .. }| {
                    let key = SpanStr::from_str(key.as_str());
                    let value = otel_value_to_dd_scalar(value);
                    (key, value)
                })
                .collect();
            DdSpanEvent {
                time_unix_nano,
                name,
                attributes,
            }
        })
        .collect();
    tag_span_if_contains_exception(&mut dd_span);

    if !otel_span.span_context.trace_state().header().is_empty() {
        dd_span.meta.insert(
            SpanStr::from_static_str("w3c.tracestate"),
            SpanStr::from_string(otel_span.span_context.trace_state().header()),
        );
    }

    let lib_name = otel_span.instrumentation_scope.name();
    if !lib_name.is_empty() {
        dd_span.meta.insert(
            SpanStr::from_static_str(semconv::attribute::OTEL_SCOPE_NAME),
            SpanStr::from_str(lib_name),
        );
    }

    let lib_version = otel_span.instrumentation_scope.version();
    if let Some(version) = lib_version {
        if !version.is_empty() {
            dd_span.meta.insert(
                SpanStr::from_static_str(semconv::attribute::OTEL_SCOPE_VERSION),
                SpanStr::from_str(version),
            );
        }
    }

    // Code from the OTLP protocol
    // https://github.com/open-telemetry/opentelemetry-proto/blob/724e427879e3d2bae2edc0218fff06e37b9eb46e/opentelemetry/proto/trace/v1/trace.proto#L268
    dd_span.meta.insert(
        SpanStr::from_static_str(semconv::attribute::OTEL_STATUS_CODE),
        SpanStr::from_static_str(match &otel_span.status {
            opentelemetry::trace::Status::Unset => "Unset",
            opentelemetry::trace::Status::Ok => "Ok",
            opentelemetry::trace::Status::Error { .. } => "Error",
        }),
    );
    if let opentelemetry::trace::Status::Error { description } = &otel_span.status {
        if !description.is_empty() {
            dd_span.meta.insert(
                SpanStr::from_static_str(semconv::attribute::OTEL_STATUS_DESCRIPTION),
                SpanStr::from_str(description.as_ref()),
            );
        }
    }

    if ["error.message", "error.type", "error.stack"]
        .into_iter()
        .any(|k| !dd_span.meta.contains_key(&SpanStr::from_static_str(k)))
    {
        dd_span.error = status_to_error(otel_span.status, &mut dd_span);
    }

    dd_span
}

#[cfg(test)]
mod tests {
    use opentelemetry::{SpanId, TraceId};

    use crate::mappings::transform::otel_span_id_to_dd_id;

    use super::otel_trace_id_to_dd_id;

    #[test]
    fn trace_id_conversion() {
        let (low, up) = otel_trace_id_to_dd_id(TraceId::from_bytes([1; 16]));
        assert_eq!(low, 0x0101010101010101);
        assert_eq!(up, 0x0101010101010101);
    }

    #[test]
    fn span_id_conversion() {
        let id = otel_span_id_to_dd_id(SpanId::from_bytes([2; 8]));
        assert_eq!(id, 0x0202020202020202);
    }
}

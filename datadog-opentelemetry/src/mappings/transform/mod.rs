// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Transform
//!
//! This code has been ported from the otlp receiver in the datadog agent.
//!
//! # Source
//!
//! This should be a 1:1 port of this commit
//! <https://github.com/DataDog/datadog-agent/blob/97e6db0d4130c8545ede77111a2590eb034c2f11/pkg/trace/transform/transform.go>
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
//!
//! # Allocations
//!
//! The converted spans have a scoped lifetime (they live until the trace chunk has been
//! sent), so all strings produced by the conversion are allocated in a [`Bump`] arena
//! passed down by the exporter. Formatted strings are stored in [`SpanStr`] as borrowed
//! `&'a str`s pointing into the arena, avoiding per-span `String` allocations through
//! the global allocator. Strings that already live long enough (span data, resource
//! attributes, config) are borrowed directly.

pub mod attribute_keys;
pub mod otel_util;
pub mod semconv_shim;

#[cfg(feature = "test-utils")]
pub mod transform_tests;

use attribute_keys::*;
use otel_util::*;

use std::borrow::{Borrow, Cow};
use std::fmt::Write;

use bumpalo::Bump;
use libdd_trace_utils::span::v1::{AttributeValue, SpanKind as DdSpanKind};
use libdd_trace_utils::span::vec_map::VecMap;
use libdd_trace_utils::span::SpanText;
use opentelemetry::{
    trace::{Link, SpanKind},
    Key, KeyValue, Value,
};
use opentelemetry_sdk::Resource;
pub use opentelemetry_semantic_conventions as semconv;

use crate::core::constants::SAMPLING_RATE_EVENT_EXTRACTION_KEY;

use super::sdk_span::SdkSpan;

pub type SpanStr<'a> = CowStr<'a>;
pub type DdSpan<'a> = libdd_trace_utils::span::v1::Span<CowStr<'a>>;
pub type DdTraceChunk<'a> = libdd_trace_utils::span::v1::TraceChunk<CowStr<'a>>;
type DdSpanEvent<'a> = libdd_trace_utils::span::v1::SpanEvent<CowStr<'a>>;
type DdSpanLink<'a> = libdd_trace_utils::span::v1::SpanLink<CowStr<'a>>;
pub type DdAttributeValue<'a> = AttributeValue<CowStr<'a>>;

/// Inserts a string tag (a v0.4 `meta` entry) on the span.
///
/// `env`, `version`, `component` and `span.kind` are dedicated span fields in v1, every other
/// key is stored as a string attribute.
pub(crate) fn meta_insert<'a>(dd_span: &mut DdSpan<'a>, k: SpanStr<'a>, v: SpanStr<'a>) {
    match k.as_str() {
        "env" => dd_span.env = v,
        "version" => dd_span.version = v,
        "component" => dd_span.component = v,
        "span.kind" => dd_span.span_kind = DdSpanKind::from_meta(v.as_str()),
        _ => dd_span.attributes.insert(k, AttributeValue::String(v)),
    }
}

/// Returns the string tag (a v0.4 `meta` entry) stored under `k`, if any.
pub(crate) fn meta_get<'s, 'a>(dd_span: &'s DdSpan<'a>, k: &str) -> Option<&'s SpanStr<'a>> {
    let promoted = match k {
        "env" => &dd_span.env,
        "version" => &dd_span.version,
        "component" => &dd_span.component,
        _ => {
            return match dd_span.attributes.get(k)? {
                AttributeValue::String(v) => Some(v),
                _ => None,
            }
        }
    };
    (!promoted.as_str().is_empty()).then_some(promoted)
}

pub(crate) fn meta_contains(dd_span: &DdSpan, k: &str) -> bool {
    meta_get(dd_span, k).is_some()
}

/// Inserts a numeric tag (a v0.4 `metrics` entry) on the span.
pub(crate) fn metric_insert<'a>(dd_span: &mut DdSpan<'a>, k: SpanStr<'a>, v: f64) {
    dd_span.attributes.insert(k, AttributeValue::Float(v));
}

pub(crate) fn metric_contains(dd_span: &DdSpan, k: &str) -> bool {
    dd_span
        .attributes
        .iter()
        .any(|(key, v)| key.as_str() == k && matches!(v, AttributeValue::Float(_)))
}

fn set_meta_otlp<'a>(k: SpanStr<'a>, v: SpanStr<'a>, dd_span: &mut DdSpan<'a>) {
    match k.borrow() {
        "operation.name" => dd_span.name = v,
        "service.name" => dd_span.service = v,
        "resource.name" => dd_span.resource = v,
        "span.type" => dd_span.r#type = v,
        "analytics.event" => {
            let parsed = if v.as_str().eq_ignore_ascii_case("true") {
                true
            } else if v.as_str().eq_ignore_ascii_case("false") {
                false
            } else {
                return;
            };
            metric_insert(
                dd_span,
                SpanStr::from_static_str(SAMPLING_RATE_EVENT_EXTRACTION_KEY),
                if parsed { 1.0 } else { 0.0 },
            );
        }
        _ => meta_insert(dd_span, k, v),
    }
}

fn set_meta_otlp_with_semconv_mappings<'a>(
    k: &'a str,
    value: &'a opentelemetry::Value,
    dd_span: &mut DdSpan<'a>,
    alloc: &'a Bump,
) {
    let mapped_key = get_dd_key_for_otlp_attribute_in(k, alloc);
    if mapped_key.is_empty() {
        return;
    }
    let mapped_key = SpanStr::from_cow(mapped_key);
    if is_meta_key(mapped_key.as_str())
        && !meta_get(dd_span, mapped_key.as_str())
            .map(|v| v.as_str().is_empty())
            .unwrap_or(true)
    {
        return;
    }
    set_meta_otlp(
        mapped_key,
        SpanStr::from_str(otel_value_string_repr(value, alloc)),
        dd_span,
    );
}

fn set_metric_otlp<'a>(s: &mut DdSpan<'a>, k: SpanStr<'a>, v: f64) {
    match k.as_str() {
        "sampling.priority" => {
            metric_insert(s, SpanStr::from_static_str("_sampling_priority_v1"), v);
        }
        _ => metric_insert(s, k, v),
    }
}

fn set_metric_otlp_with_semconv_mappings<'a>(
    k: &'a str,
    value: f64,
    dd_span: &mut DdSpan<'a>,
    alloc: &'a Bump,
) {
    let mapped_key = get_dd_key_for_otlp_attribute_in(k, alloc);
    let mapped_key = SpanStr::from_cow(mapped_key);

    if !mapped_key.as_str().is_empty() {
        // Unlike v0.4's separate `meta` and `metrics`, v1 spans have a single attribute
        // namespace: a metric must not override the string tag already set for a meta key.
        if is_meta_key(mapped_key.as_str())
            && (metric_contains(dd_span, mapped_key.as_str())
                || meta_contains(dd_span, mapped_key.as_str()))
        {
            return;
        }
        set_metric_otlp(dd_span, mapped_key, value);
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L69
///
/// `dd_span` is expected to be empty: either a default span or a span recycled from a pool, whose
/// collections keep their capacity.
fn otel_span_to_dd_span_minimal<'a>(
    mut dd_span: DdSpan<'a>,
    span: &SpanExtractArgs<'a, '_>,
    is_top_level: bool,
) -> DdSpan<'a> {
    let alloc = span.alloc;
    let start = time_as_unix_nanos(span.span.start_time);
    let end = time_as_unix_nanos(span.span.end_time);

    dd_span.service = SpanStr::from_str(span.get_attr_str(DATADOG_SERVICE));
    dd_span.name = SpanStr::from_str(span.get_attr_str(DATADOG_NAME));
    dd_span.resource = SpanStr::from_str(span.get_attr_str(DATADOG_RESOURCE));
    dd_span.r#type = SpanStr::from_str(span.get_attr_str(DATADOG_TYPE));
    dd_span.span_id = otel_span_id_to_dd_id(span.span.span_context.span_id());
    dd_span.parent_id = otel_span_id_to_dd_id(span.span.parent_span_id);
    dd_span.start = start;
    // duration should not be negative
    dd_span.duration = end.checked_sub(start).unwrap_or(0).max(0);
    // We will likely put _sampling_priority, maybe _dd.measured, top level
    // And by default tracing tags by code.line.number, thread.id and busy_ns/idle_ns
    //
    // Why 6? This seems like a good number to prevent small reallocations while not
    // using too much memory. A recycled span keeps the capacity it grew to.
    if dd_span.attributes.capacity() == 0 {
        dd_span.attributes = VecMap::with_capacity(span.attr_len() + span.res_len() + 6);
    }
    if let Some(error) = span.get_attr_num::<i32>(DATADOG_ERROR) {
        dd_span.error = error != 0;
    } else if matches!(span.span.status, opentelemetry::trace::Status::Error { .. }) {
        dd_span.error = true;
    }

    dd_span.span_kind = match span.get_attr_str_opt(DATADOG_SPAN_KIND) {
        Some(span_kind) => DdSpanKind::from_meta(span_kind),
        None => match span.span_kind() {
            SpanKind::Client => DdSpanKind::Client,
            SpanKind::Server => DdSpanKind::Server,
            SpanKind::Producer => DdSpanKind::Producer,
            SpanKind::Consumer => DdSpanKind::Consumer,
            SpanKind::Internal => DdSpanKind::Internal,
        },
    };

    if dd_span.service.as_str().is_empty() {
        dd_span.service = SpanStr::from_str(get_otel_service(span));
    }

    if dd_span.name.as_str().is_empty() {
        dd_span.name = SpanStr::from_str(get_otel_operation_name_v2(span));
    }

    if dd_span.resource.as_str().is_empty() {
        dd_span.resource = SpanStr::from_str(get_otel_resource_v2(span));
    }
    if dd_span.r#type.as_str().is_empty() {
        dd_span.r#type = SpanStr::from_str(get_otel_span_type(span));
    }
    let code: u32 = if let Some(http_status_code) = span.get_attr_num(DATADOG_HTTP_STATUS_CODE) {
        http_status_code
    } else {
        get_otel_status_code(span).unwrap_or(0)
    };
    if code != 0 {
        meta_insert(
            &mut dd_span,
            SpanStr::from_static_str("http.status_code"),
            SpanStr::from_str(fmt_in(alloc, format_args!("{code}"))),
        );
    }

    if is_top_level {
        metric_insert(&mut dd_span, SpanStr::from_static_str("_top_level"), 1.0);
    }
    if span.get_attr_num(DD_MEASURED) == Some(1)
        || matches!(span.span_kind(), SpanKind::Client | SpanKind::Producer)
    {
        metric_insert(&mut dd_span, SpanStr::from_static_str("_dd.measured"), 1.0);
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

fn time_as_unix_nanos(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L495
fn status_to_error<'a>(
    status: &'a opentelemetry::trace::Status,
    dd_span: &mut DdSpan<'a>,
    alloc: &'a Bump,
) -> bool {
    if !matches!(status, opentelemetry::trace::Status::Error { .. }) {
        return false;
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
            if let Some(attr) = e.attributes.get(otel_key) {
                dd_span.attributes.insert(
                    SpanStr::from_static_str(dd_key),
                    AttributeValue::String(dd_value_to_string(attr, alloc)),
                );
            }
        }
    }
    if meta_contains(dd_span, "error.message") {
        return true;
    }
    let error_msg = match status {
        opentelemetry::trace::Status::Error { description, .. } if !description.is_empty() => {
            // The description lives in the otel span, borrow it directly
            Some(SpanStr::from_str(description.as_ref()))
        }
        _ => ["http.response.status_code", "http.status_code"]
            .into_iter()
            .find_map(|key| meta_get(dd_span, key))
            .map(|code| match meta_get(dd_span, "http.status_text") {
                Some(http_text) => SpanStr::from_str(fmt_in(
                    alloc,
                    format_args!("{} {}", code.as_str(), http_text.as_str()),
                )),
                None => code.clone(),
            }),
    };
    if let Some(error_msg) = error_msg {
        meta_insert(
            dd_span,
            SpanStr::from_static_str("error.message"),
            error_msg,
        );
    }

    true
}

/// https://github.com/DataDog/datadog-agent/blob/a4dea246effb49f2781b451a5b60aa2524fbef75/pkg/trace/transform/transform.go#L328
fn tag_span_if_contains_exception(dd_span: &mut DdSpan) {
    if dd_span
        .span_events
        .iter()
        .any(|e| e.name.as_str().eq_ignore_ascii_case("exception"))
    {
        meta_insert(
            dd_span,
            SpanStr::from_static_str("_dd.span_events.has_exception"),
            SpanStr::from_static_str("true"),
        );
    }
}

fn otel_value_to_dd_attribute<'a>(value: &'a Value, alloc: &'a Bump) -> DdAttributeValue<'a> {
    fn map_vec<'a, T: 'a>(
        v: impl IntoIterator<Item = T>,
        constructor: fn(T) -> DdAttributeValue<'a>,
    ) -> DdAttributeValue<'a> {
        AttributeValue::List(v.into_iter().map(constructor).collect::<Vec<_>>())
    }
    match value {
        opentelemetry::Value::I64(i) => AttributeValue::Int(*i),
        opentelemetry::Value::F64(f) => AttributeValue::Float(*f),
        opentelemetry::Value::Bool(b) => AttributeValue::Bool(*b),
        opentelemetry::Value::Array(opentelemetry::Array::Bool(v)) => {
            map_vec(v.iter().copied(), AttributeValue::Bool)
        }
        opentelemetry::Value::Array(opentelemetry::Array::I64(v)) => {
            map_vec(v.iter().copied(), AttributeValue::Int)
        }
        opentelemetry::Value::Array(opentelemetry::Array::F64(v)) => {
            map_vec(v.iter().copied(), AttributeValue::Float)
        }
        opentelemetry::Value::Array(opentelemetry::Array::String(v)) => map_vec(
            v.iter().map(|s| SpanStr::from_str(s.as_str())),
            AttributeValue::String,
        ),
        _ => AttributeValue::String(SpanStr::from_str(otel_value_string_repr(value, alloc))),
    }
}

fn dd_value_to_string<'a>(value: &DdAttributeValue<'a>, alloc: &'a Bump) -> SpanStr<'a> {
    fn write_value(value: &DdAttributeValue, w: &mut bumpalo::collections::String<'_>) {
        let _ = match value {
            AttributeValue::String(s) => write!(w, "{}", s.as_str()),
            AttributeValue::Int(i) => write!(w, "{i}"),
            AttributeValue::Float(d) => write!(w, "{d}"),
            AttributeValue::Bool(b) => write!(w, "{b}"),
            AttributeValue::List(values) => {
                w.push('[');
                for (i, v) in values.iter().enumerate() {
                    if i != 0 {
                        w.push(',');
                    }
                    write_value(v, w);
                }
                w.push(']');
                Ok(())
            }
            // Never produced by the otel -> dd mapping.
            AttributeValue::Bytes(_) | AttributeValue::KeyValue(_) => Ok(()),
        };
    }
    if let AttributeValue::String(s) = value {
        // Cheap Cow clone: free when the string is borrowed, which is the case
        // for all strings produced by the conversion (span data or arena)
        return s.clone();
    }
    let mut w = bumpalo::collections::String::new_in(alloc);
    write_value(value, &mut w);
    SpanStr::from_str(w.into_bump_str())
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
    alloc: &'a Bump,
    span_attrs: AttributeIndices,
}

impl<'a, 'b> SpanExtractArgs<'a, 'b> {
    pub fn new(span: &'b SdkSpan<'a>, resource: &'a Resource, alloc: &'a Bump) -> Self {
        let span_attrs = AttributeIndices::from_attribute_slice(span.attributes);
        Self {
            span,
            span_attrs,
            resource,
            alloc,
        }
    }
}

impl<'a> OtelSpan<'a> for SpanExtractArgs<'a, '_> {
    fn alloc(&self) -> &'a Bump {
        self.alloc
    }

    fn name(&self) -> &'a str {
        self.span.name
    }

    fn span_kind(&self) -> SpanKind {
        self.span.span_kind.clone()
    }

    fn has_attr(&self, attr_key: AttributeKey) -> bool {
        self.span_attrs.get(attr_key).is_some()
    }

    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<&'a str> {
        let idx = self.span_attrs.get(attr_key)?;
        let v = &self.span.attributes.get(idx)?.value;
        Some(otel_value_string_repr(v, self.alloc))
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

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<&'a Value> {
        self.resource.get_ref(&Key::from_static_str(attr_key.key()))
    }

    fn res_len(&self) -> usize {
        self.resource.len()
    }
}

pub fn otel_value_string_repr<'a>(v: &'a Value, alloc: &'a Bump) -> &'a str {
    match v {
        Value::Bool(true) => "true",
        Value::Bool(false) => "false",
        Value::I64(0) => "0",
        Value::I64(1) => "1",
        Value::I64(i) => fmt_in(alloc, format_args!("{i}")),
        Value::F64(0.0) => "0",
        Value::F64(1.0) => "1",
        Value::F64(i) => fmt_in(alloc, format_args!("{i}")),
        Value::String(string_value) => string_value.as_str(),
        Value::Array(a) => fmt_in(alloc, format_args!("{a}")),
        // Value is #[non_exhaustive]
        _ => fmt_in(alloc, format_args!("{v}")),
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

    /// Copies `s` into the arena `alloc`, producing a string that lives as long as
    /// the arena. Used for short-lived owned strings (e.g. the tracestate `header()`
    /// `String`) that must outlive the span conversion.
    pub fn from_bump(alloc: &'a Bump, s: &str) -> Self {
        Self(Cow::Borrowed(alloc.alloc_str(s)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<String> for CowStr<'_> {
    fn from(s: String) -> Self {
        Self::from_string(s)
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

    fn from_owned(value: String) -> Self {
        CowStr(Cow::Owned(value))
    }
}

impl<'a> libdd_trace_utils::span::TraceData for CowStr<'a> {
    type Text = CowStr<'a>;

    type Bytes = libdd_tinybytes::Bytes;
}

/// Converts an OpenTelemetry span to a new Datadog span, see [`otel_span_to_dd_span_into`].
#[cfg(any(test, feature = "test-utils"))]
pub fn otel_span_to_dd_span<'a>(
    otel_span: &SdkSpan<'a>,
    otel_resource: &'a Resource,
    alloc: &'a Bump,
) -> DdSpan<'a> {
    otel_span_to_dd_span_into(DdSpan::default(), otel_span, otel_resource, alloc)
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
///
/// `dd_span` is filled instead of allocating a new span. It is expected to be empty, typically a
/// span recycled from a [`TracePool`](libdd_trace_utils::span::v1::chunk_pool::TracePool): its
/// collections keep their capacity, which avoids reallocating them.
///
/// `alloc` is the arena backing every string formatted during the conversion; it must
/// outlive the returned `DdSpan`.
pub fn otel_span_to_dd_span_into<'a>(
    dd_span: DdSpan<'a>,
    otel_span: &SdkSpan<'a>,
    otel_resource: &'a Resource,
    alloc: &'a Bump,
) -> DdSpan<'a> {
    // There is a performance optimization possible here:
    // The otlp receiver splits span conversion into two steps
    // 1. The minimal fields used by Stats computation
    // 2. The rest of the fields
    //
    // If we use CSS we could probably do only 1. if we know the span is going to be dropped before
    // being sent...

    let span_extracted = SpanExtractArgs::new(otel_span, otel_resource, alloc);

    // Top level spans are computed later
    let is_top_level = false;
    let mut dd_span = otel_span_to_dd_span_minimal(dd_span, &span_extracted, is_top_level);

    for (dd_semantics_key, meta_key) in DD_SEMANTICS_KEY_TO_META_KEY {
        let value = span_extracted.get_attr_str(*dd_semantics_key);
        if !value.is_empty() {
            meta_insert(
                &mut dd_span,
                SpanStr::from_static_str(meta_key),
                SpanStr::from_str(value),
            );
        }
    }

    for (key, value) in otel_resource.iter() {
        set_meta_otlp_with_semconv_mappings(key.as_str(), value, &mut dd_span, alloc);
    }

    for opentelemetry::KeyValue { key, value, .. } in otel_span.instrumentation_scope.attributes() {
        let key = SpanStr::from_str(key.as_str());
        let value = SpanStr::from_str(otel_value_string_repr(value, alloc));
        meta_insert(&mut dd_span, key, value);
    }
    meta_insert(
        &mut dd_span,
        SpanStr::from_static_str("otel.trace_id"),
        SpanStr::from_str(fmt_in(
            alloc,
            format_args!(
                "{:032x}",
                u128::from_be_bytes(otel_span.span_context.trace_id().to_bytes())
            ),
        )),
    );

    if dd_span.version.as_str().is_empty() {
        let version = otel_resource
            .get_ref(&Key::from_static_str(SERVICE_VERSION.key()))
            .map(|v| otel_value_string_repr(v, alloc))
            .unwrap_or_default();
        if !version.is_empty() {
            dd_span.version = SpanStr::from_str(version);
        }
    }

    for KeyValue { key, value, .. } in otel_span.attributes {
        let key = key.as_str();
        if key.starts_with("datadog.") {
            continue;
        }
        match value {
            opentelemetry::Value::I64(v) => {
                set_metric_otlp_with_semconv_mappings(key, *v as f64, &mut dd_span, alloc);
            }
            opentelemetry::Value::F64(v) => {
                set_metric_otlp_with_semconv_mappings(key, *v, &mut dd_span, alloc);
            }
            _ => {
                set_meta_otlp_with_semconv_mappings(key, value, &mut dd_span, alloc);
            }
        }
    }

    if dd_span.env.as_str().is_empty() {
        let env = get_otel_env(&span_extracted);
        if !env.is_empty() {
            dd_span.env = SpanStr::from_str(env);
        }
    }

    // `extend` rather than `collect` to reuse the capacity of a recycled span.
    dd_span.span_links.extend(otel_span.links.iter().map(
        |Link {
             span_context,
             attributes: otel_attributes,
             ..
         }| {
            let attributes = otel_attributes
                .iter()
                .map(|KeyValue { key, value, .. }| {
                    (
                        SpanStr::from_str(key.as_str()),
                        otel_value_to_dd_attribute(value, alloc),
                    )
                })
                .collect();
            // TraceState has no borrowed serialization API, so build the header
            // String and copy it into the arena
            let mut tracestate = bumpalo::collections::String::new_in(alloc);
            for (i, (k, v)) in span_context.trace_state().into_iter().enumerate() {
                if i > 0 {
                    tracestate.push(',');
                }
                let _ = write!(tracestate, "{k}={v}");
            }
            DdSpanLink {
                trace_id: span_context.trace_id().to_bytes(),
                span_id: otel_span_id_to_dd_id(span_context.span_id()),
                attributes,
                tracestate: SpanStr::from_str(tracestate.into_bump_str()),
                flags: span_context.trace_flags().to_u8() as u32,
            }
        },
    ));
    dd_span.span_events.extend(otel_span.events.iter().map(|e| {
        let attributes = e
            .attributes
            .iter()
            .map(|KeyValue { key, value, .. }| {
                (
                    SpanStr::from_str(key.as_str()),
                    otel_value_to_dd_attribute(value, alloc),
                )
            })
            .collect();
        DdSpanEvent {
            time_unix_nano: time_as_unix_nanos(e.timestamp).max(0) as u64,
            name: SpanStr::from_str(e.name.as_ref()),
            attributes,
        }
    }));
    tag_span_if_contains_exception(&mut dd_span);

    // TraceState has no borrowed serialization API, build the header String once and
    // copy it into the arena if present
    let tracestate_header = otel_span.span_context.trace_state().header();
    if !tracestate_header.is_empty() {
        meta_insert(
            &mut dd_span,
            SpanStr::from_static_str("w3c.tracestate"),
            SpanStr::from_bump(alloc, &tracestate_header),
        );
    }

    let lib_name = otel_span.instrumentation_scope.name();
    if !lib_name.is_empty() {
        meta_insert(
            &mut dd_span,
            SpanStr::from_static_str(semconv::attribute::OTEL_SCOPE_NAME),
            SpanStr::from_str(lib_name),
        );
    }

    let lib_version = otel_span.instrumentation_scope.version();
    if let Some(version) = lib_version {
        if !version.is_empty() {
            meta_insert(
                &mut dd_span,
                SpanStr::from_static_str(semconv::attribute::OTEL_SCOPE_VERSION),
                SpanStr::from_str(version),
            );
        }
    }

    // Code from the OTLP protocol
    // https://github.com/open-telemetry/opentelemetry-proto/blob/724e427879e3d2bae2edc0218fff06e37b9eb46e/opentelemetry/proto/trace/v1/trace.proto#L268
    meta_insert(
        &mut dd_span,
        SpanStr::from_static_str(semconv::attribute::OTEL_STATUS_CODE),
        SpanStr::from_static_str(match &otel_span.status {
            opentelemetry::trace::Status::Unset => "Unset",
            opentelemetry::trace::Status::Ok => "Ok",
            opentelemetry::trace::Status::Error { .. } => "Error",
        }),
    );
    if let opentelemetry::trace::Status::Error { description } = &otel_span.status {
        if !description.is_empty() {
            meta_insert(
                &mut dd_span,
                SpanStr::from_static_str(semconv::attribute::OTEL_STATUS_DESCRIPTION),
                SpanStr::from_str(description.as_ref()),
            );
        }
    }

    if ["error.message", "error.type", "error.stack"]
        .into_iter()
        .any(|k| !meta_contains(&dd_span, k))
    {
        dd_span.error = status_to_error(otel_span.status, &mut dd_span, alloc);
    }

    dd_span
}

#[cfg(test)]
mod tests {
    use opentelemetry::SpanId;

    use crate::mappings::transform::otel_span_id_to_dd_id;

    #[test]
    fn span_id_conversion() {
        let id = otel_span_id_to_dd_id(SpanId::from_bytes([2; 8]));
        assert_eq!(id, 0x0202020202020202);
    }
}

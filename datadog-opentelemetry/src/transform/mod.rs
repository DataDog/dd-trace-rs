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
//!   don't need backward comatibility.
//! * The `ignore_missing_datadog_fields=true` option. This is false by default in the agent anyway
//!
//! # Datastructures
//!
//! The original otlp receiver does OLTP -> agent span struct conversion.
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

mod attribute_keys;
mod otel_util;
mod semconv;

#[cfg(test)]
mod transform_tests;

pub use otel_util::DEFAULT_OTLP_SERVICE_NAME;

use attribute_keys::*;
use otel_util::*;

use std::{borrow::Cow, collections::hash_map};

use datadog_trace_utils::span::{
    AttributeAnyValue, AttributeAnyValueBytes as DdAnyValue, AttributeArrayValue,
    AttributeArrayValueBytes as DdScalarValue, SpanBytes as DdSpan, SpanEventBytes as DdEvent,
    SpanLinkBytes as DdSpanLink,
};
use opentelemetry::{
    trace::{Link, SpanKind},
    Key, KeyValue, SpanId,
};
use opentelemetry_sdk::Resource;
use tinybytes::BytesString;

use crate::ddtrace_transform::ExportSpan;

struct SpanExtractArgs<'a> {
    span: &'a ExportSpan,
    span_attrs: AttributeIndices,
}

impl OtelSpan for SpanExtractArgs<'_> {
    fn name(&self) -> Cow<'static, str> {
        self.span.name.clone()
    }

    fn span_kind(&self) -> SpanKind {
        self.span.span_kind.clone()
    }

    fn has_attr(&self, attr_key: AttributeKey) -> bool {
        self.span_attrs.get(attr_key).is_some()
    }

    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>> {
        let idx = self.span_attrs.get(attr_key)?;
        let kv = self.span.attributes.get(idx)?;
        Some(Cow::Owned(kv.value.to_string()))
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
}

fn set_meta_otlp(k: BytesString, v: BytesString, dd_span: &mut DdSpan) {
    match k.as_str() {
        "operation.name" => dd_span.name = v,
        "service.name" => dd_span.service = v,
        "resource.name" => dd_span.resource = v,
        "span.type" => dd_span.r#type = v,
        "analytics.event" => {
            if let Ok(parsed) = v.as_str().parse::<bool>() {
                dd_span.metrics.insert(
                    BytesString::from_static(dd_trace::constants::SAMPLING_RATE_EVENT_EXTRACTION),
                    if parsed { 1.0 } else { 0.0 },
                );
            }
        }
        _ => {
            dd_span.meta.insert(k, v);
        }
    }
}

fn set_meta_otlp_with_semconv_mappings(
    k: &str,
    value: &opentelemetry::Value,
    dd_span: &mut DdSpan,
) {
    let mapped_key = get_dd_key_for_otlp_attribute(k);
    if mapped_key.is_empty() {
        return;
    }
    let mapped_key = BytesString::from_cow(mapped_key);
    if is_meta_key(mapped_key.as_ref())
        && !dd_span
            .meta
            .get(&mapped_key)
            .map(BytesString::is_empty)
            .unwrap_or(true)
    {
        return;
    }
    set_meta_otlp(
        mapped_key,
        BytesString::from_string(value.to_string()),
        dd_span,
    );
}

fn set_metric_otlp(s: &mut DdSpan, k: BytesString, v: f64) {
    match k.as_ref() {
        "sampling.priority" => {
            s.metrics
                .insert(BytesString::from_static("_sampling_priority_v1"), v);
        }
        _ => {
            s.metrics.insert(k, v);
        }
    }
}

fn set_metric_otlp_with_semconv_mappings(k: &str, value: f64, dd_span: &mut DdSpan) {
    let mapped_key = get_dd_key_for_otlp_attribute(k);
    let mapped_key = BytesString::from_cow(mapped_key);

    if !mapped_key.is_empty() {
        if is_meta_key(mapped_key.as_str()) && dd_span.metrics.contains_key(&mapped_key) {
            return;
        }
        set_metric_otlp(dd_span, mapped_key, value);
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L69
fn otel_span_to_dd_span_minimal(
    span: &SpanExtractArgs,
    res: &Resource,
    is_top_level: bool,
) -> DdSpan {
    let (trace_id_lower_half, _) = otel_trace_id_to_dd_id(span.span.span_context.trace_id());
    let span_id = otel_span_id_to_dd_id(span.span.span_context.span_id());
    let parent_id = otel_span_id_to_dd_id(span.span.parent_span_id);
    let start = time_as_unix_nanos(span.span.start_time);
    let end = time_as_unix_nanos(span.span.end_time);
    // duration should not be negative
    let duration = end.checked_sub(start).unwrap_or(0).max(0);

    let mut dd_span = DdSpan {
        service: BytesString::from_cow(span.get_attr_str(DATADOG_SERVICE)),
        name: BytesString::from_cow(span.get_attr_str(DATADOG_NAME)),
        resource: BytesString::from_cow(span.get_attr_str(DATADOG_RESOURCE)),
        r#type: BytesString::from_cow(span.get_attr_str(DATADOG_TYPE)),
        trace_id: trace_id_lower_half,
        span_id,
        parent_id,
        start,
        duration,
        ..Default::default()
    };
    if let Some(error) = span.get_attr_num(DATADOG_ERROR) {
        dd_span.error = error;
    } else if matches!(span.span.status, opentelemetry::trace::Status::Error { .. }) {
        dd_span.error = 1;
    }

    if let Some(span_kind) = span.get_attr_str_opt(DATADOG_SPAN_KIND) {
        dd_span.meta.insert(
            BytesString::from_static("span.kind"),
            BytesString::from_cow(span_kind),
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
            BytesString::from("span.kind"),
            BytesString::from_static(span_kind_str),
        );
    }

    if dd_span.service.is_empty() {
        dd_span.service = BytesString::from_cow(get_otel_service(res));
    }

    if dd_span.name.is_empty() {
        dd_span.name = BytesString::from_cow(get_otel_operation_name_v2(span));
    }

    if dd_span.resource.is_empty() {
        dd_span.resource = BytesString::from_cow(get_otel_resource_v2(span, res));
    }
    if dd_span.r#type.is_empty() {
        dd_span.r#type = BytesString::from_cow(get_otel_span_type(span, res));
    }
    let code: u32 = if let Some(http_status_code) = span.get_attr_num(DATADOG_HTTP_STATUS_CODE) {
        http_status_code
    } else {
        get_otel_status_code(span)
    };
    if code != 0 {
        dd_span
            .metrics
            .insert(BytesString::from("http.status_code"), code as f64);
    }

    if is_top_level {
        dd_span
            .metrics
            .insert(BytesString::from_static("_top_level"), 1.0);
    }
    if span.get_attr_num(DD_MEASURED) == Some(1)
        || matches!(span.span_kind(), SpanKind::Client | SpanKind::Producer)
    {
        dd_span
            .metrics
            .insert(BytesString::from_static("_dd.measured"), 1.0);
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
            (semconv::ATTRIBUTE_EXCEPTION_MESSAGE, "error.msg"),
            (semconv::ATTRIBUTE_EXCEPTION_TYPE, "error.type"),
            (semconv::ATTRIBUTE_EXCEPTION_STACKTRACE, "error.stack"),
        ] {
            if let Some(attr) = e.attributes.get(&BytesString::from_static(otel_key)) {
                dd_span
                    .meta
                    .insert(BytesString::from_static(dd_key), dd_value_to_string(attr));
            }
        }
    }
    let error_msg_key = BytesString::from_static("error.msg");
    if let hash_map::Entry::Vacant(error_msg_slot) = dd_span.meta.entry(error_msg_key.clone()) {
        match status {
            opentelemetry::trace::Status::Error { description, .. } if !description.is_empty() => {
                error_msg_slot.insert(BytesString::from_cow(description.clone()));
            }
            _ => {
                for key in ["http.response.status_code", "http.status_code"] {
                    let Some(code) = dd_span.meta.get(&BytesString::from_static(key)) else {
                        continue;
                    };
                    if let Some(http_text) = dd_span
                        .meta
                        .get(&BytesString::from_static("http.status_text"))
                    {
                        dd_span.meta.insert(
                            error_msg_key,
                            BytesString::from(format!("{} {}", code.as_str(), http_text.as_str())),
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
            BytesString::from_static("_dd.span_events.has_exception"),
            "true".into(),
        );
    }
}

fn otel_value_to_dd_scalar(value: opentelemetry::Value) -> AttributeAnyValue<BytesString> {
    fn map_vec<T>(
        v: impl IntoIterator<Item = T>,
        construtor: fn(T) -> DdScalarValue,
    ) -> DdAnyValue {
        DdAnyValue::Array(v.into_iter().map(construtor).collect::<Vec<_>>())
    }
    match value {
        opentelemetry::Value::I64(i) => DdAnyValue::SingleValue(DdScalarValue::Integer(i)),
        opentelemetry::Value::F64(f) => DdAnyValue::SingleValue(DdScalarValue::Double(f)),
        opentelemetry::Value::Bool(b) => DdAnyValue::SingleValue(DdScalarValue::Boolean(b)),
        opentelemetry::Value::String(s) => DdAnyValue::SingleValue(DdScalarValue::String(
            BytesString::from_string(s.to_string()),
        )),
        opentelemetry::Value::Array(opentelemetry::Array::Bool(v)) => {
            map_vec(v, DdScalarValue::Boolean)
        }
        opentelemetry::Value::Array(opentelemetry::Array::I64(v)) => {
            map_vec(v, DdScalarValue::Integer)
        }
        opentelemetry::Value::Array(opentelemetry::Array::F64(v)) => {
            map_vec(v, DdScalarValue::Double)
        }
        opentelemetry::Value::Array(opentelemetry::Array::String(v)) => map_vec(
            v.into_iter()
                .map(|s| BytesString::from_string(s.to_string())),
            DdScalarValue::String,
        ),
        _ => DdAnyValue::SingleValue(DdScalarValue::String(BytesString::from_string(
            value.to_string(),
        ))),
    }
}

fn dd_value_to_string(value: &AttributeAnyValue<BytesString>) -> BytesString {
    use std::fmt::Write;
    fn write_scalar(value: &AttributeArrayValue<BytesString>, w: &mut String) {
        let _ = match value {
            AttributeArrayValue::String(s) => write!(w, "{}", s.as_str()),
            AttributeArrayValue::Integer(i) => write!(w, "{}", i),
            AttributeArrayValue::Double(d) => write!(w, "{}", d),
            AttributeArrayValue::Boolean(b) => write!(w, "{}", b),
        };
    }
    fn write_vec(value: &[AttributeArrayValue<BytesString>], w: &mut String) {
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
        AttributeAnyValue::SingleValue(AttributeArrayValue::String(s)) => s.clone(),
        AttributeAnyValue::SingleValue(attribute_array_value) => {
            let mut w = String::new();
            write_scalar(attribute_array_value, &mut w);
            BytesString::from(w)
        }
        AttributeAnyValue::Array(attribute_array_values) => {
            let mut w = String::new();
            write_vec(attribute_array_values, &mut w);
            BytesString::from(w)
        }
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/transform/transform.go#L217
const DD_SEMANTICS_KEY_TO_META_KEY: &[(AttributeKey, &str)] = &[
    (DATADOG_ENV, "env"),
    (DATADOG_VERSION, "version"),
    (DATADOG_HTTP_STATUS_CODE, "http.status_code"),
    (DATADOG_ERROR_MSG, "error.msg"),
    (DATADOG_ERROR_TYPE, "error.type"),
    (DATADOG_ERROR_STACK, "error.stack"),
];

/// Checks that the key is in the list of dd keys mapped from meta keys
fn is_meta_key(key: &str) -> bool {
    matches!(
        key,
        "env" | "version" | "http.status_code" | "error.msg" | "error.type" | "error.stack"
    )
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
pub fn otel_span_to_dd_span(otel_span: ExportSpan, otel_resource: &Resource) -> DdSpan {
    // There is a performance otpimization possible here:
    // The otlp receiver splits span conversion into two steps
    // 1. The minimal fields used by Stats computation
    // 2. The rest of the fields
    //
    // If we use CSS we could probably do only 1. if we know the span is going to be dropped before
    // being sent...

    let span_attrs = AttributeIndices::from_attribute_slice(&otel_span.attributes);
    let span_extracted = SpanExtractArgs {
        span: &otel_span,
        span_attrs,
    };
    let is_top_level = otel_span.parent_span_id == SpanId::INVALID
        || matches!(otel_span.span_kind, SpanKind::Server | SpanKind::Consumer);

    let mut dd_span = otel_span_to_dd_span_minimal(&span_extracted, otel_resource, is_top_level);

    for (dd_semantics_key, meta_key) in DD_SEMANTICS_KEY_TO_META_KEY {
        let value = span_extracted.get_attr_str(*dd_semantics_key);
        if !value.is_empty() {
            dd_span.meta.insert(
                BytesString::from_static(meta_key),
                BytesString::from_cow(value),
            );
        }
    }

    for (key, value) in otel_resource.iter() {
        set_meta_otlp_with_semconv_mappings(key.as_str(), value, &mut dd_span);
    }

    for opentelemetry::KeyValue { key, value, .. } in otel_span.instrumentation_scope.attributes() {
        let key = BytesString::from_string(key.to_string());
        let value = BytesString::from_string(value.to_string());
        dd_span.meta.insert(key, value);
    }
    let otel_trace_id = format!(
        "{:032x}",
        u128::from_be_bytes(otel_span.span_context.trace_id().to_bytes())
    );
    dd_span.meta.insert(
        BytesString::from_static("otel.trace_id"),
        BytesString::from_string(otel_trace_id),
    );

    if let hash_map::Entry::Vacant(version_slot) =
        dd_span.meta.entry(BytesString::from_static("version"))
    {
        let version = otel_resource
            .get(&Key::from_static_str(SERVICE_VERSION.key()))
            .map(|v| v.to_string())
            .unwrap_or_default();
        if !version.is_empty() {
            version_slot.insert(BytesString::from_string(version));
        }
    }

    for KeyValue { key, value, .. } in &otel_span.attributes {
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

    if let hash_map::Entry::Vacant(env_slot) = dd_span.meta.entry(BytesString::from_static("env")) {
        let env = get_otel_env(otel_resource);
        if !env.is_empty() {
            env_slot.insert(BytesString::from_cow(env));
        }
    }

    dd_span.span_links = otel_span
        .links
        .into_iter()
        .map(
            |Link {
                 span_context,
                 attributes: otel_attributes,
                 ..
             }| {
                let (trace_id, trace_id_high) = otel_trace_id_to_dd_id(span_context.trace_id());
                let span_id = otel_span_id_to_dd_id(span_context.span_id());
                let tracestate = BytesString::from(span_context.trace_state().header());
                let flags = span_context.trace_flags().to_u8() as u64;
                let attributes = otel_attributes
                    .into_iter()
                    .map(|KeyValue { key, value, .. }| {
                        let key = BytesString::from(key.to_string());
                        let value = BytesString::from(value.to_string());
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
        .into_iter()
        .map(|e| {
            let time_unix_nano = time_as_unix_nanos(e.timestamp).max(0) as u64;
            let name = BytesString::from_cow(e.name);
            let attributes = e
                .attributes
                .into_iter()
                .map(|KeyValue { key, value, .. }| {
                    let key = BytesString::from(key.to_string());
                    let value = otel_value_to_dd_scalar(value);
                    (key, value)
                })
                .collect();
            DdEvent {
                time_unix_nano,
                name,
                attributes,
            }
        })
        .collect();
    tag_span_if_contains_exception(&mut dd_span);

    if !otel_span.span_context.trace_state().header().is_empty() {
        dd_span.meta.insert(
            BytesString::from_static("w3c.tracestate"),
            BytesString::from_string(otel_span.span_context.trace_state().header()),
        );
    }

    let lib_name = otel_span.instrumentation_scope.name();
    if !lib_name.is_empty() {
        dd_span.meta.insert(
            BytesString::from_static(semconv::ATTRIBUTE_OTEL_LIBRARY_NAME),
            BytesString::from_string(lib_name.to_owned()),
        );
    }

    let lib_version = otel_span.instrumentation_scope.version();
    if let Some(version) = lib_version {
        if !version.is_empty() {
            dd_span.meta.insert(
                BytesString::from_static(semconv::ATTRIBUTE_OTEL_LIBRARY_VERSION),
                BytesString::from_string(version.to_owned()),
            );
        }
    }

    // Code from the OTLP protocol
    // https://github.com/open-telemetry/opentelemetry-proto/blob/724e427879e3d2bae2edc0218fff06e37b9eb46e/opentelemetry/proto/trace/v1/trace.proto#L268
    dd_span.meta.insert(
        BytesString::from_static(semconv::ATTRIBUTE_OTEL_STATUS_CODE),
        BytesString::from_static(match &otel_span.status {
            opentelemetry::trace::Status::Unset => "Unset",
            opentelemetry::trace::Status::Ok => "Ok",
            opentelemetry::trace::Status::Error { .. } => "Error",
        }),
    );
    if let opentelemetry::trace::Status::Error { description } = &otel_span.status {
        if !description.is_empty() {
            dd_span.meta.insert(
                BytesString::from_static(semconv::ATTRIBUTE_OTEL_STATUS_DESCRIPTION),
                BytesString::from_cow(description.clone()),
            );
        }
    }

    if ["error.msg", "error.type", "error.stack"]
        .into_iter()
        .any(|k| !dd_span.meta.contains_key(&BytesString::from_static(k)))
    {
        dd_span.error = status_to_error(&otel_span.status, &mut dd_span);
    }

    dd_span
}

#[cfg(test)]
mod tests {
    use opentelemetry::{SpanId, TraceId};

    use crate::transform::otel_span_id_to_dd_id;

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

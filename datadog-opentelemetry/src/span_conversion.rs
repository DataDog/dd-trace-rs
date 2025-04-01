// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use datadog_trace_utils::span::{
    SpanBytes as DdSpan, SpanEventBytes as DdEvent, SpanLinkBytes as DdSpanLink,
};
use dd_trace::constants::{HIGHER_ORDER_TRACE_ID_BITS_TAG, SAMPLING_PRIORITY_TAG, SPAN_KIND_TAG};
use opentelemetry::{
    trace::{SpanContext, SpanKind},
    KeyValue,
};
use opentelemetry_sdk::trace::SpanData;
use tinybytes::BytesString;

// Transform a vector of opentelemetry span data into a vector of datadog tracechunks
pub fn otel_span_data_to_trace_chunks(
    cfg: &dd_trace::Config,
    span_data: Vec<SpanData>,
) -> Vec<Vec<DdSpan>> {
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    span_data
        .into_iter()
        .map(|s| (s.span_context.trace_id(), otel_span_to_dd_span(cfg, s)))
        .fold(HashMap::new(), |mut acc, (trace_id, span)| {
            acc.entry(trace_id).or_insert(Vec::new()).push(span);
            acc
        })
        .into_values()
        .collect()
}

fn extract_otel_attributes(span: &SpanData) -> &'static str {
    match span.span_kind {
        // TODO(paullgdc): Port the db type logic from here
        // https://github.com/DataDog/datadog-agent/blob/e3c8284f80e3003058ab93799fd45d1eb8717e8e/pkg/trace/traceutil/otel_util.go#L250
        SpanKind::Client => "http",
        SpanKind::Server => "web",
        SpanKind::Producer | SpanKind::Consumer | SpanKind::Internal => "custom",
    }
}

fn otel_span_kind_to_meta_span_kind(span_kind: opentelemetry::trace::SpanKind) -> BytesString {
    match span_kind {
        SpanKind::Client => BytesString::from("client"),
        SpanKind::Server => BytesString::from("server"),
        SpanKind::Producer => BytesString::from("producer"),
        SpanKind::Consumer => BytesString::from("consumer"),
        SpanKind::Internal => BytesString::from("internal"),
    }
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

fn otel_span_attributes_to_meta(
    attributes: Vec<opentelemetry::KeyValue>,
) -> (HashMap<BytesString, BytesString>, HashMap<BytesString, f64>) {
    let mut meta = HashMap::with_capacity(attributes.len());
    let mut metrics = HashMap::new();

    for KeyValue { key, value, .. } in attributes {
        // TODO(paullgdc): The logic in the otlp receiver here is a lot more complex
        // Some attributes are mapped to span field like ressources/service/etc
        let key = BytesString::from(key.to_string());
        match value {
            opentelemetry::Value::I64(v) => {
                metrics.insert(key, v as f64);
            }
            opentelemetry::Value::F64(v) => {
                metrics.insert(key, v);
            }
            _ => {
                meta.insert(key, BytesString::from(value.to_string()));
            }
        }
    }
    (meta, metrics)
}

fn otel_sampling_decision_to_metrics(
    span_context: &SpanContext,
    metrics: &mut HashMap<BytesString, f64>,
) {
    metrics
        .entry(BytesString::from(SAMPLING_PRIORITY_TAG))
        .or_insert(match span_context.trace_flags().is_sampled() {
            true => 1.0,
            false => 0.0,
        });
}

fn otel_span_to_dd_span(cfg: &dd_trace::Config, otel_span: SpanData) -> DdSpan {
    // There is a performance otpimization possible here:
    // The otlp receiver splits span conversion into two steps
    // 1. The minimal fields used by Stats computation
    // 2. The rest of the fields
    //
    // If we use CSS we could probably do only 1. if we know the span is going to be dropped before
    // being sent...

    let (trace_id_lower_half, trace_id_upper_half) =
        otel_trace_id_to_dd_id(otel_span.span_context.trace_id());
    let span_id = otel_span_id_to_dd_id(otel_span.span_context.span_id());
    let parent_id = otel_span_id_to_dd_id(otel_span.parent_span_id);
    let span_type = BytesString::from(extract_otel_attributes(&otel_span));
    let start = time_as_unix_nanos(otel_span.start_time);
    let end = time_as_unix_nanos(otel_span.end_time);
    // duration should not be negative
    let duration = end.checked_sub(start).unwrap_or(0).max(0);

    // TODO(paullgdc): operation name
    // https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L405
    let name = BytesString::from_cow(otel_span.name);
    // TODO(paullgdc): resource name from attributes extraction
    // https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L332C6-L332C23
    let resource = name.clone();
    let span_links = otel_span
        .links
        .into_iter()
        .map(|l| {
            let (trace_id, trace_id_high) = otel_trace_id_to_dd_id(l.span_context.trace_id());
            let span_id = otel_span_id_to_dd_id(l.span_context.span_id());
            let tracestate = BytesString::from(l.span_context.trace_state().header());
            let flags = l.span_context.trace_flags().to_u8() as u64;
            // TODO(paullgdc): attributes conversion
            let attributes = HashMap::new();
            DdSpanLink {
                trace_id,
                trace_id_high,
                span_id,
                attributes,
                tracestate,
                flags,
            }
        })
        .collect();
    let span_events = otel_span
        .events
        .into_iter()
        .map(|e| {
            let time_unix_nano = time_as_unix_nanos(e.timestamp).max(0) as u64;
            let name = BytesString::from_cow(e.name);
            // TODO(paullgdc): attributes conversion
            let attributes = HashMap::new();
            DdEvent {
                time_unix_nano,
                name,
                attributes,
            }
        })
        .collect();
    let error = 0;
    let (mut meta, mut metrics) = otel_span_attributes_to_meta(otel_span.attributes);
    meta.insert(
        BytesString::from(HIGHER_ORDER_TRACE_ID_BITS_TAG),
        BytesString::from(format!("{:016x}", trace_id_upper_half)),
    );
    meta.insert(
        BytesString::from(SPAN_KIND_TAG),
        BytesString::from(otel_span_kind_to_meta_span_kind(otel_span.span_kind)),
    );
    otel_sampling_decision_to_metrics(&otel_span.span_context, &mut metrics);
    // TODO(paullgdc):
    // * the otlp receiver also converts "datadog.<>" attributes to their matching fields
    // * Map the status code
    // * Map error field for error sampler
    // * top level detection and analzed span mapping

    DdSpan {
        name,
        // TODO: service name should probably be an arc if we copy it around
        service: BytesString::from(cfg.service().to_owned()),
        // TODO(paullgdc): resource name from attributes extraction
        resource,
        r#type: span_type,
        trace_id: trace_id_lower_half,
        span_id,
        parent_id,
        start,
        duration,
        error,
        meta,
        metrics,
        meta_struct: HashMap::new(),
        span_links,
        span_events,
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::{SpanId, TraceId};

    use crate::span_conversion::otel_span_id_to_dd_id;

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

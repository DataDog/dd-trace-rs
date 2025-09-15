// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

/// A span exported from the OpenTelemetry SDK
///
/// We don't use the `opentelemetry_sdk::trace::SpanData` because it's not
/// constructible so we can't create it and use to write tests on the span conversion
#[derive(Debug, Clone)]
pub struct SdkSpan<'a> {
    pub span_context: &'a opentelemetry::trace::SpanContext,
    pub parent_span_id: opentelemetry::trace::SpanId,
    pub span_kind: opentelemetry::trace::SpanKind,
    pub name: &'a str,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub attributes: &'a [opentelemetry::KeyValue],
    #[allow(dead_code)]
    pub dropped_attributes_count: u32,
    pub events: &'a [opentelemetry::trace::Event],
    #[allow(dead_code)]
    pub dropped_event_count: u32,
    pub links: &'a [opentelemetry::trace::Link],
    #[allow(dead_code)]
    pub dropped_links_count: u32,
    pub status: &'a opentelemetry::trace::Status,
    pub instrumentation_scope: &'a opentelemetry::InstrumentationScope,
}

impl<'a> SdkSpan<'a> {
    pub fn from_sdk_span_data(span: &'a opentelemetry_sdk::trace::SpanData) -> Self {
        Self {
            span_context: &span.span_context,
            parent_span_id: span.parent_span_id,
            span_kind: span.span_kind.clone(),
            name: span.name.as_ref(),
            start_time: span.start_time,
            end_time: span.end_time,
            attributes: &span.attributes,
            dropped_attributes_count: span.dropped_attributes_count,
            events: &span.events.events,
            dropped_event_count: span.events.dropped_count,
            links: &span.links.links,
            dropped_links_count: span.links.dropped_count,
            status: &span.status,
            instrumentation_scope: &span.instrumentation_scope,
        }
    }
}

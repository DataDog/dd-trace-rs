// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Explicit error fields, OTel/HTTP status classification and exception/event values.

use std::time::SystemTime;

use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{Span as _, SpanBuilder, SpanKind, Status, TracerProvider},
    KeyValue,
};
use opentelemetry_sdk::trace::SdkTracerProvider;

use super::{start_span, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Explicit error flags, error tags and HTTP status fields
    MappingCase {
        name: "dd_fields__error_flag_cleared_by_unset_status",
        configure: None,
        resource: None,
        run: dd_fields_error_flag_cleared_by_unset_status,
    },
    MappingCase {
        name: "dd_fields__error_flag_zero",
        configure: None,
        resource: None,
        run: dd_fields_error_flag_zero,
    },
    MappingCase {
        name: "dd_fields__error_semconv_fields",
        configure: None,
        resource: None,
        run: dd_fields_error_semconv,
    },
    MappingCase {
        name: "dd_fields__http_status_code",
        configure: None,
        resource: None,
        run: dd_fields_http_status_code,
    },
    MappingCase {
        name: "dd_fields__explicit_error_status_matrix",
        configure: None,
        resource: None,
        run: explicit_error_matrix,
    },
    // Exceptions and typed event attributes
    MappingCase {
        name: "events__exception_with_error_status",
        configure: None,
        resource: None,
        run: events_exception_with_error_status,
    },
    MappingCase {
        name: "events__exception_without_error_status",
        configure: None,
        resource: None,
        run: events_exception_without_error_status,
    },
    MappingCase {
        name: "events__typed_attributes",
        configure: None,
        resource: None,
        run: events_typed_attributes,
    },
    MappingCase {
        name: "events__explicit_exception_status_precedence",
        configure: None,
        resource: None,
        run: exception_precedence,
    },
    // OTel status and HTTP error classification
    MappingCase {
        name: "status__ok",
        configure: None,
        resource: None,
        run: status_ok,
    },
    MappingCase {
        name: "status__error_description",
        configure: None,
        resource: None,
        run: status_error_description,
    },
    MappingCase {
        name: "status__error_http_code_no_text",
        configure: None,
        resource: None,
        run: status_error_http_code_no_text,
    },
    MappingCase {
        name: "status__error_http_code_with_text",
        configure: None,
        resource: None,
        run: status_error_http_code_with_text,
    },
    MappingCase {
        name: "status__error_no_message",
        configure: None,
        resource: None,
        run: status_error_no_message,
    },
    MappingCase {
        name: "status__http_server_error_cleared_tags",
        configure: None,
        resource: None,
        run: status_http_server_error_cleared_tags,
    },
    MappingCase {
        name: "status__http_server_error_kept",
        configure: None,
        resource: None,
        run: status_http_server_error_kept,
    },
    MappingCase {
        name: "status__http_client_error_status",
        configure: None,
        resource: None,
        run: status_http_client_error_status,
    },
    MappingCase {
        name: "status__http_boundaries_and_ok_override",
        configure: None,
        resource: None,
        run: http_boundaries,
    },
];

/// Unset OTel status clears `datadog.error=1` when the error-tag triple is absent.
fn dd_fields_error_flag_cleared_by_unset_status(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "error-flag",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.error", 1)],
    ));
}

/// `datadog.error=0` leaves the span a non-error.
fn dd_fields_error_flag_zero(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "error-flag-zero",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.error", 0)],
    ));
}

/// `datadog.error.{msg,type,stack}` map to the `error.{message,type,stack}` tags.
/// They don't set the error flag on their own.
fn dd_fields_error_semconv(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "error-semconv-fields",
        SpanKind::Internal,
        vec![
            KeyValue::new("datadog.error.msg", "semconv boom"),
            KeyValue::new("datadog.error.type", "ValueError"),
            KeyValue::new(
                "datadog.error.stack",
                "ValueError: semconv boom\n  at mapping",
            ),
        ],
    ));
}

/// `datadog.http_status_code` sets the `http.status_code` tag; on a server span a 503
/// is also an error per the default HTTP server error statuses.
fn dd_fields_http_status_code(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "http-status-semconv",
        SpanKind::Server,
        vec![KeyValue::new("datadog.http_status_code", 503)],
    ));
}

/// A complete triple skips status fallback; partial triples do not. Any nonzero flag
/// marks the span as an error (v1 spans carry a boolean error, so negative values are
/// normalized to an error).
fn explicit_error_matrix(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for flag in [0_i64, 1, -7] {
        for tags in [0, 1, 3] {
            for status in [
                Status::Unset,
                Status::Ok,
                Status::error("status description"),
            ] {
                let name = format!("flag={flag},tags={tags},status={status:?}");
                let mut attrs = vec![KeyValue::new("datadog.error", flag)];
                for key in [
                    "datadog.error.msg",
                    "datadog.error.type",
                    "datadog.error.stack",
                ]
                .into_iter()
                .take(tags)
                {
                    attrs.push(KeyValue::new(key, "explicit"));
                }
                let mut span = SpanBuilder::from_name(name)
                    .with_attributes(attrs)
                    .start(&provider.tracer("mapping"));
                span.set_status(status);
            }
        }
    }
}

/// An `exception` event on an errored span provides the error tags and sets
/// `_dd.span_events.has_exception`.
fn events_exception_with_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "exception-span", SpanKind::Client, vec![]);
    span.add_event(
        "exception",
        vec![
            KeyValue::new("exception.message", "event boom"),
            KeyValue::new("exception.type", "TypeError"),
            KeyValue::new(
                "exception.stacktrace",
                "TypeError: event boom\n  at mapping",
            ),
        ],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// The `exception` event name is matched case-insensitively, and without an error
/// status the error tags are not set.
fn events_exception_without_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "exception-span", SpanKind::Internal, vec![]);
    span.add_event(
        "Exception",
        vec![
            KeyValue::new("exception.message", "event boom"),
            KeyValue::new("exception.type", "TypeError"),
            KeyValue::new(
                "exception.stacktrace",
                "TypeError: event boom\n  at mapping",
            ),
        ],
    );
    drop(span);
}

/// Span events keep their typed attribute values (numbers stay numbers), unlike span
/// and link attributes which are flattened or stringified.
///
/// Note: array-valued event attributes are mapped by the tracer (they would stay
/// arrays in the v1 payload), but the test agent's v1 -> v0.4 downgrade rejects them
/// (`Array of strings values are not supported yet`), so they can't be pinned down
/// in a snapshot yet.
fn events_typed_attributes(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "events-span", SpanKind::Internal, vec![]);
    span.add_event_with_timestamp(
        "custom.event",
        SystemTime::now(),
        vec![
            KeyValue::new("event.string", "value"),
            KeyValue::new("event.int", 7),
            KeyValue::new("event.float", 0.25),
            KeyValue::new("event.bool", true),
        ],
    );
    span.add_event("bare.event", vec![]);
    drop(span);
}

fn exception_precedence(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for complete in [false, true] {
        let mut attrs = vec![KeyValue::new("datadog.error.msg", "explicit message")];
        if complete {
            attrs.extend([
                KeyValue::new("datadog.error.type", "explicit type"),
                KeyValue::new("datadog.error.stack", "explicit stack"),
            ]);
        }
        let mut span = emit_error_span(provider, complete, attrs);
        for message in ["first exception", "last exception"] {
            span.add_event(
                "exception",
                vec![
                    KeyValue::new("exception.message", message),
                    KeyValue::new("exception.type", "event type"),
                    KeyValue::new("exception.stacktrace", "event stack"),
                ],
            );
        }
    }
}

fn emit_error_span(
    provider: &SdkTracerProvider,
    complete: bool,
    attrs: Vec<KeyValue>,
) -> opentelemetry_sdk::trace::Span {
    let mut span = SpanBuilder::from_name(format!("complete={complete}"))
        .with_attributes(attrs)
        .start(&provider.tracer("mapping"));
    span.set_status(Status::error("status description"));
    span
}

fn status_ok(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "ok-span", SpanKind::Server, vec![]);
    span.set_status(Status::Ok);
    drop(span);
}

/// An error status with a description becomes `error.message` and
/// `otel.status_description`.
fn status_error_description(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "error-span", SpanKind::Client, vec![]);
    span.set_status(Status::error("disk full"));
    drop(span);
}

/// An error status without a description and without exception events falls back to
/// the HTTP status code for `error.message`.
fn status_error_http_code_no_text(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Client,
        vec![KeyValue::new("http.response.status_code", 404)],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// `http.status_text` is appended to the status code in `error.message`.
fn status_error_http_code_with_text(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Client,
        vec![
            KeyValue::new("http.response.status_code", 404),
            KeyValue::new("http.status_text", "Not Found"),
        ],
    );
    span.set_status(Status::error(""));
    drop(span);
}

/// An error status with no description, no exception event and no HTTP status code
/// marks the span as an error without an `error.message` tag.
fn status_error_no_message(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(provider, "error-span", SpanKind::Producer, vec![]);
    span.set_status(Status::error(""));
    drop(span);
}

/// A server span with a 4xx status code is not an error per the default HTTP server
/// error statuses: the error set by the OTel status is cleared, together with the
/// error tags it produced.
fn status_http_server_error_cleared_tags(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 404)],
    );
    span.set_status(Status::error("gone"));
    drop(span);
}

/// A server span with a 5xx status code keeps the error and its tags.
fn status_http_server_error_kept(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let mut span = start_span(
        provider,
        "error-span",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 500)],
    );
    span.set_status(Status::error("boom"));
    drop(span);
}

/// A client span with a 4xx status code is an error per the default HTTP client
/// error statuses, even with an unset OTel status.
fn status_http_client_error_status(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "client-error-span",
        SpanKind::Client,
        vec![KeyValue::new("http.response.status_code", 404)],
    ));
}

fn http_boundaries(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    http_kind_overrides(provider);
    for kind in [SpanKind::Server, SpanKind::Client, SpanKind::Internal] {
        for code in [
            0_i64, 199, 200, 299, 300, 399, 400, 499, 500, 599, 600, 65535, 65536, -1,
        ] {
            for error in [false, true] {
                let mut span = SpanBuilder::from_name(format!("{kind:?}:{code}:error={error}"))
                    .with_kind(kind.clone())
                    .with_attributes(vec![KeyValue::new("http.response.status_code", code)])
                    .start(&provider.tracer("mapping"));
                span.set_status(if error {
                    Status::error("description")
                } else {
                    Status::Ok
                });
            }
        }
    }
}

/// Datadog kind controls final HTTP errors, while the API kind still controls
/// type inference. The wrong-case override must not act like `server`.
fn http_kind_overrides(provider: &SdkTracerProvider) {
    for (api_kind, dd_kind, code, status) in [
        (SpanKind::Server, "client", 404, Status::Unset),
        (SpanKind::Server, "producer", 404, Status::error("boom")),
        (SpanKind::Client, "server", 404, Status::error("boom")),
        (SpanKind::Server, "Server", 503, Status::Unset),
    ] {
        let mut span = SpanBuilder::from_name(format!("api={api_kind:?},dd={dd_kind},code={code}"))
            .with_kind(api_kind)
            .with_attributes(vec![
                KeyValue::new("datadog.span.kind", dd_kind),
                KeyValue::new("http.response.status_code", code),
            ])
            .start(&provider.tracer("mapping"));
        span.set_status(status);
    }
}

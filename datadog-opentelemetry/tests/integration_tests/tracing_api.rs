// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, thread, time::Duration};

use opentelemetry::{
    trace::{TraceContextExt, TracerProvider},
    Context,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::integration_tests::{assert_subset, make_extractor, with_test_agent_session};

#[tokio::test]
async fn test_smoke() {
    const SESSION_NAME: &str = "tracing_api/test_smoke";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_log_level_filter(dd_trace::log::LevelFilter::Debug);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, _, _| {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
        let _guard = subscriber.set_default();

        let span = tracing::trace_span!("test_span", _sampling_priority_v1 = 2);
        span.in_scope(|| {
            {
                tracing::trace_span!("child_span_1")
            };
            {
                tracing::trace_span!("child_span_2")
            };
        });
    })
    .await;
}

#[tokio::test]
async fn test_remote_span_extraction_propagation() {
    const SESSION_NAME: &str = "tracing_api/test_remote_span_extraction_propagation";
    let cfg = dd_trace::Config::builder();
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
        let _guard = subscriber.set_default();

        let extractor = make_extractor([
            ("x-datadog-trace-id", "1234"),
            ("x-datadog-parent-id", "5678"),
            ("x-datadog-sampling-priority", "2"),
            ("x-datadog-tags", "_dd.p.foo=bar"),
            ("x-datadog-origin", "my_origin"),
        ]);
        let mut injected = HashMap::new();
        let mut child_span_id = 0;

        let span = tracing::trace_span!("test_span");
        let ctx = propagator.extract_with_context(&Context::default(), &extractor);
        span.set_parent(ctx);
        span.in_scope(|| {
            let child_span = tracing::trace_span!("child_span");
            propagator.inject_context(&child_span.context(), &mut injected);
            child_span_id = u64::from_be_bytes(
                child_span
                    .context()
                    .span()
                    .span_context()
                    .span_id()
                    .to_bytes(),
            );
        });
        let expected_parent_id = format!("{}", child_span_id);

        assert_subset(
            injected.iter().map(|(k, v_)| (k.as_str(), v_.as_str())),
            [
                ("x-datadog-trace-id", "1234"),
                ("x-datadog-parent-id", expected_parent_id.as_str()),
                ("x-datadog-sampling-priority", "2"),
                ("x-datadog-tags", "_dd.p.foo=bar"),
                ("x-datadog-origin", "my_origin"),
            ],
        );
    })
    .await;
}

#[tokio::test]
async fn test_debug_open_spans() {
    const SESSION_NAME: &str = "tracing_api/test_debug_open_spans";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_log_level_filter(dd_trace::log::LevelFilter::Off)
        .set_trace_debug_open_spans(true)
        .set_trace_debug_open_spans_timeout(Duration::from_millis(1))
        .__internal_set_span_metrics_interval(Duration::from_millis(100));
    let _logger_guard = dd_trace::log::test_logger::activate_test_logger();
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, _, _| {
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")));
        let _guard = subscriber.set_default();

        // leak a span
        let _root_span = tracing::trace_span!("root_span").entered();
        std::mem::forget(tracing::trace_span!("child_span"));
        thread::sleep(Duration::from_millis(200));


        let test_logs = dd_trace::log::test_logger::take_test_logs().unwrap();
        let abandoned_logs = test_logs
            .iter()
            .filter(|(lvl, msg)| {
                *lvl == dd_trace::log::Level::Warn
                    && msg.contains("possibly abandoned trace")
                    && msg.contains("root_name=root_span")
            })
            .collect::<Vec<_>>();
        assert!(abandoned_logs.len() >= 1)
    })
    .await;

    let test_logs = dd_trace::log::test_logger::take_test_logs().unwrap();
    let abandoned_logs = test_logs
        .iter()
        .filter(|(lvl, msg)| {
            *lvl == dd_trace::log::Level::Warn
                && msg.contains("lost trace not finished during shutdown")
                && msg.contains("root_name=root_span")
        })
        .collect::<Vec<_>>();
    assert!(abandoned_logs.len() >= 1)
}

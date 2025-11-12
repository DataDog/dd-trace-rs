// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::thread;
use std::time::Duration;
use std::{collections::HashMap, ops::Deref, sync::Arc};

use datadog_opentelemetry::make_test_tracer;
use dd_trace::configuration::{SamplingRuleConfig, TracePropagationStyle};
use opentelemetry::global::ObjectSafeSpan;
use opentelemetry::trace::{
    mark_span_as_active, SamplingDecision, SamplingResult, SpanBuilder, TraceContextExt,
    TraceState, Tracer, TracerProvider,
};
use opentelemetry::Context;

use crate::integration_tests::{
    assert_subset, make_extractor, make_test_agent, with_test_agent_session,
};

#[tokio::test]
async fn test_received_traces() {
    const SESSION_NAME: &str = "opentelemetry_api/test_received_traces";
    with_test_agent_session(
        SESSION_NAME,
        dd_trace::Config::builder(),
        |_, tracer_provider, _, _| {
            let tracer = tracer_provider.tracer("test");
            for decision in [
                SamplingDecision::RecordOnly,
                SamplingDecision::RecordAndSample,
            ] {
                {
                    let base_ctx = Context::new();
                    let span = SpanBuilder::from_name("test")
                        .with_kind(opentelemetry::trace::SpanKind::Client)
                        .with_sampling_result(SamplingResult {
                            decision,
                            attributes: vec![],
                            trace_state: TraceState::default(),
                        })
                        .start_with_context(&tracer, &base_ctx);
                    drop(span)
                };
            }
        },
    )
    .await;
}

#[tokio::test]
async fn test_injection_extraction() {
    const SESSION_NAME: &str = "opentelemetry_api/test_injection_extraction";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_log_level_filter(dd_trace::log::LevelFilter::Debug);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let parent_ctx = propagator.extract(&make_extractor([
            (
                "traceparent",
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01",
            ),
            (
                "tracestate",
                "dd=p:00f067aa0ba902b7;s:2;o:rum;t.dm:-4;t.usr.id:baz64",
            ),
        ]));
        let _guard = parent_ctx.attach();

        let mut injected = HashMap::new();

        let tracer = tracer_provider.tracer("test");
        {
            let span = SpanBuilder::from_name("test_parent")
                .with_kind(opentelemetry::trace::SpanKind::Server)
                .start(&tracer);
            let _ctx = Context::current_with_span(span).attach();
            {
                let child_span = SpanBuilder::from_name("test_child")
                    .with_kind(opentelemetry::trace::SpanKind::Client)
                    .start(&tracer);
                let _child_ctx = Context::current_with_span(child_span).attach();

                propagator.inject(&mut injected);
            }
        }

        assert_subset(
            injected.iter().map(|(k, v_)| (k.as_str(), v_.as_str())),
            [
                ("x-datadog-origin", "rum"),
                ("x-datadog-sampling-priority", "2"),
                ("x-datadog-trace-id", "7277407061855694839"),
            ],
        );

        assert_subset(
            injected.get("x-datadog-tags").unwrap().split(','),
            ["_dd.p.dm=-4", "_dd.p.usr.id=baz64"],
        );

        assert_subset(
            injected
                .get("tracestate")
                .unwrap()
                .strip_prefix("dd=")
                .unwrap()
                .split(';'),
            ["s:2", "o:rum", "t.tid:80f198ee56343ba8", "t.dm:-4"],
        );
        assert_subset(
            injected
                .get("traceparent")
                .unwrap()
                .strip_prefix("00-")
                .unwrap()
                .splitn(3, '-'),
            ["01", "80f198ee56343ba864fe8b2a57d3eff7"],
        );
    })
    .await;
}

#[tokio::test]
async fn test_sampling_extraction() {
    const SESSION_NAME: &str = "opentelemetry_api/test_sampling_extraction";

    let mut config_builder = dd_trace::Config::builder();
    config_builder.set_service("my_service_name".to_string());
    config_builder.set_trace_sampling_rules(vec![SamplingRuleConfig {
        service: Some("my_service_name".to_string()),
        sample_rate: 1.0,
        ..SamplingRuleConfig::default()
    }]);
    config_builder.set_trace_propagation_style(vec![TracePropagationStyle::TraceContext]);
    with_test_agent_session(
        SESSION_NAME,
        config_builder,
        |_, tracer_provider, propagator, _| {
            let mut injected = HashMap::new();
            let trace_id;
            let span_id;
            let tracer = tracer_provider.tracer("test");
            {
                let span = SpanBuilder::from_name("test_parent")
                    .with_kind(opentelemetry::trace::SpanKind::Server)
                    .start(&tracer);
                let _ctx: opentelemetry::ContextGuard = Context::current_with_span(span).attach();
                {
                    let child_span = SpanBuilder::from_name("test_child")
                        .with_kind(opentelemetry::trace::SpanKind::Client)
                        .start(&tracer);
                    trace_id = child_span.span_context().trace_id();
                    span_id = child_span.span_context().span_id();

                    let _child_ctx = Context::current_with_span(child_span).attach();

                    propagator.inject(&mut injected);
                }
            }
            assert_subset(
                injected
                    .get("tracestate")
                    .unwrap()
                    .strip_prefix("dd=")
                    .unwrap()
                    .split(';')
                    .map(String::from),
                [
                    "s:2".to_string(),
                    "t.dm:-3".to_string(),
                    format!("p:{span_id:016x}"),
                ],
            );

            assert_subset(
                injected.into_iter(),
                [(
                    "traceparent".to_string(),
                    format!("00-{trace_id:032x}-{span_id:016x}-01"),
                )],
            );
        },
    )
    .await
}

#[tokio::test]
async fn test_remote_config_sampling_rates() {
    const SESSION_NAME: &str = "opentelemetry_api/test_remote_config_sampling_rates";
    let test_agent = make_test_agent(SESSION_NAME).await;

    test_agent
        .set_remote_config_response(
            r##"{
            "path": "datadog/2/APM_TRACING/1234/config",
            "msg": {
                "id": "42",
                "lib_config": {
                    "tracing_sampling_rules": [
                        {
                            "resource": "test-span",
                            "sample_rate": 1.0,
                            "provenance": "customer"
                        }
                    ]
                }
            }
        }"##,
            None,
        )
        .await;

    let config = dd_trace::Config::builder()
        .set_trace_agent_url(test_agent.get_base_uri().await.to_string().into())
        .set_trace_sampling_rules(vec![dd_trace::SamplingRuleConfig {
            resource: Some("test-span".into()),
            sample_rate: 0.0,
            ..Default::default()
        }])
        .set_log_level_filter(dd_trace::log::LevelFilter::Debug)
        .build();
    let config = Arc::new(config);

    let (tracer_provider, _propagator) = make_test_tracer(config.clone());
    // Wait for the config to be applied
    // TODO(paullgdc): If this test is flaky this is probably it, fetching the config took more
    // than 2 seconds  We should probably have a way to sleep until the config is
    // applied, but this is a bit convoluted
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert_eq!(
        config.trace_sampling_rules().deref(),
        vec![dd_trace::SamplingRuleConfig {
            resource: Some("test-span".into()),
            sample_rate: 1.0,
            provenance: "customer".into(),
            ..Default::default()
        }]
    );

    drop(SpanBuilder::from_name("test-span").start(&tracer_provider.tracer("test")));

    tracer_provider.shutdown().expect("failed to shutdown");
    test_agent.assert_snapshot(SESSION_NAME).await;
}

#[tokio::test]
/// if we extract a span without a sampling decision, we should sample it
async fn test_decision_less_extraction() {
    const SESSION_NAME: &str = "opentelemetry_api/test_decision_less_extraction";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_trace_sampling_rules(vec![dd_trace::SamplingRuleConfig {
        sample_rate: 0.0,
        ..Default::default()
    }])
    .set_log_level_filter(dd_trace::log::LevelFilter::Debug);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let extractor = make_extractor([
            ("x-datadog-trace-id", "321"),
            ("x-datadog-parent-id", "654"),
            ("x-datadog-origin", "rum"),
        ]);

        let _cx = propagator.extract(&extractor).attach();

        let _cx = Context::current()
            .with_span(SpanBuilder::from_name("test-span").start(&tracer_provider.tracer("test")))
            .attach();
        let mut injected = HashMap::new();
        propagator.inject(&mut injected);

        assert_subset(
            injected.iter().map(|(k, v)| (k.as_ref(), v.as_ref())),
            [
                ("x-datadog-sampling-priority", "-1"),
                ("x-datadog-origin", "rum"),
            ],
        );
    })
    .await;
}

#[tokio::test]
async fn test_tracing_disabled() {
    const SESSION_NAME: &str = "opentelemetry_api/test_tracing_disabled";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_enabled(false)
        .set_log_level_filter(dd_trace::log::LevelFilter::Debug);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        {
            let span = tracer_provider
                .tracer("test_tracing_disabled")
                .build(SpanBuilder {
                    name: "span_disabled".into(),
                    ..SpanBuilder::default()
                });
            let _cx = Context::new().with_span(span).attach();
            let mut injected = HashMap::new();
            propagator.inject(&mut injected);

            assert!(injected.is_empty());
        }

        let extractor = make_extractor([("x-datadog-trace-id", "321")]);

        let cx = propagator.extract(&extractor);
        assert!(!cx.has_active_span());
    })
    .await
}

#[tokio::test]
async fn test_debug_open_spans() {
    const SESSION_NAME: &str = "opentelemetry_api/test_debug_open_spans";
    let mut cfg = dd_trace::Config::builder();
    cfg.set_log_level_filter(dd_trace::log::LevelFilter::Debug)
        .set_trace_debug_open_spans(true)
        .set_trace_debug_open_spans_timeout(Duration::from_millis(1))
        .__internal_set_span_metrics_interval(Duration::from_millis(100));
    let _logger_guard = dd_trace::log::test_logger::activate_test_logger();
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, _, _| {
        let tracer = tracer_provider.tracer("test_debug_open_spans");
        let _child_span_1;
        let child_span_2;

        // leak a span
        {
            let _root = mark_span_as_active(tracer.start("root_span"));
            _child_span_1 = tracer.start("child_span");
            child_span_2 = tracer.start("child_span");
        }
        thread::sleep(Duration::from_millis(300));

        let test_logs = dd_trace::log::test_logger::take_test_logs().unwrap();
        let abandoned_logs = test_logs
            .iter()
            .filter(|(lvl, msg)| {
                *lvl == dd_trace::log::Level::Warn
                    && msg.contains("possibly abandoned trace")
                    && msg.contains("open_span_names=")
                    && msg.contains("[(child_span,2),]")
            })
            .collect::<Vec<_>>();
        assert!(!abandoned_logs.is_empty());
        std::mem::forget(child_span_2);
    })
    .await;

    let test_logs = dd_trace::log::test_logger::take_test_logs().unwrap();
    let abandoned_logs = test_logs
        .iter()
        .filter(|(lvl, msg)| {
            *lvl == dd_trace::log::Level::Warn
                && msg.contains("lost trace not finished during shutdown")
                && msg.contains("[(child_span,1),]")
        })
        .collect::<Vec<_>>();
    assert!(!abandoned_logs.is_empty())
}

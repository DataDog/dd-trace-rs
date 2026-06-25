// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;
use std::{collections::HashMap, ops::Deref, sync::Arc};

use datadog_opentelemetry::configuration::{Config, SamplingRuleConfig, TracePropagationStyle};
use datadog_opentelemetry::log::LevelFilter;
use datadog_opentelemetry::make_test_tracer;
use opentelemetry::global::ObjectSafeSpan;
use opentelemetry::trace::{
    SamplingDecision, SamplingResult, SpanBuilder, TraceContextExt, TraceState, Tracer,
    TracerProvider,
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
        Config::builder(),
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
    let mut cfg = Config::builder();
    cfg.set_log_level_filter(LevelFilter::Debug);
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

    let mut config_builder = Config::builder();
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

    let config = Config::builder()
        .set_trace_agent_url(test_agent.get_base_uri().await.to_string())
        .set_trace_sampling_rules(vec![SamplingRuleConfig {
            resource: Some("test-span".into()),
            sample_rate: 0.0,
            ..Default::default()
        }])
        .set_log_level_filter(LevelFilter::Debug)
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
        vec![SamplingRuleConfig {
            resource: Some("test-span".into()),
            sample_rate: 1.0,
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
    let mut cfg = Config::builder();
    cfg.set_trace_sampling_rules(vec![SamplingRuleConfig {
        sample_rate: 0.0,
        ..Default::default()
    }])
    .set_log_level_filter(LevelFilter::Debug);
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
    let mut cfg = Config::builder();
    cfg.set_enabled(false)
        .set_log_level_filter(LevelFilter::Debug);
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
async fn test_trace_writer_synchronous_mode() {
    const SESSION_NAME: &str = "opentelemetry_api/test_trace_writer_synchronous_mode";
    let test_agent = make_test_agent(SESSION_NAME).await;

    let mut cfg = Config::builder();
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string())
        .set_trace_writer_synchronous_write(true)
        // set async flush duration to forever...
        .set_trace_writer_max_flush_interval(Duration::from_secs(1000000000))
        .set_log_level_filter(LevelFilter::Debug);
    let config = Arc::new(cfg.build());

    let (tracer_provider, _propagator) = make_test_tracer(config.clone());
    {
        tracer_provider
            .tracer("test_trace_writer_synchronous_mode")
            .build(SpanBuilder {
                name: "span".into(),
                ..SpanBuilder::default()
            });
    }
    test_agent.assert_snapshot(SESSION_NAME).await;
}

#[tokio::test]
/// A request arrives with baggage but NO trace context.
/// The local root span must therefore receive the configured `DD_TRACE_BAGGAGE_TAG_KEYS`
/// span tags (`baggage.user.id` here) even though there is no upstream trace context — guarding the
/// `on_start` path that applies baggage tags to a local root reached without a remote parent.
async fn test_baggage_only_no_trace_context_applies_baggage_span_tags() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_baggage_only_no_trace_context_applies_baggage_span_tags";
    let mut cfg = Config::builder();
    cfg.set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        // Only a baggage header, no x-datadog-* or traceparent headers. `user.id` is one of the
        // keys tracked by the default DD_TRACE_BAGGAGE_TAG_KEYS filter.
        let parent_ctx = propagator.extract(&make_extractor([("baggage", "user.id=alice")]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        let span = SpanBuilder::from_name("test_baggage_only")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let _ctx = Context::current_with_span(span).attach();
    })
    .await;
}

#[tokio::test]
/// A request arrives with a baggage header AND a trace context. The incoming context is continued,
/// so the new span is the local root of this service (remote parent). The local root must receive
/// the configured `DD_TRACE_BAGGAGE_TAG_KEYS` span tags (`baggage.user.id` here) — guarding the
/// `on_start` remote-parent branch that applies baggage tags alongside the remote links.
async fn test_baggage_with_trace_context_applies_baggage_span_tags() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_baggage_with_trace_context_applies_baggage_span_tags";
    let mut cfg = Config::builder();
    cfg.set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        // A trace context plus a baggage header. `user.id` is one of the keys tracked by the
        // default DD_TRACE_BAGGAGE_TAG_KEYS filter.
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1234567890123456789"),
            ("x-datadog-parent-id", "987654321098765432"),
            ("x-datadog-sampling-priority", "1"),
            ("baggage", "user.id=alice"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        let span = SpanBuilder::from_name("test_baggage_with_trace_context")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let _ctx = Context::current_with_span(span).attach();
    })
    .await;
}

#[tokio::test]
/// A request arrives with a baggage header AND a trace context, then a child span is created under
/// the local root. Only the local root carries the `DD_TRACE_BAGGAGE_TAG_KEYS` span tags; the child
/// span is NOT a local root, so it must NOT receive them — guarding the `on_start` branch that
/// registers a non-root span without applying baggage tags. The snapshot shows `baggage.user.id`
/// on the root span only.
async fn test_baggage_not_applied_to_non_local_root_child() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_baggage_not_applied_to_non_local_root_child";
    let mut cfg = Config::builder();
    cfg.set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        // A trace context plus a baggage header. `user.id` is one of the keys tracked by the
        // default DD_TRACE_BAGGAGE_TAG_KEYS filter.
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1234567890123456789"),
            ("x-datadog-parent-id", "987654321098765432"),
            ("x-datadog-sampling-priority", "1"),
            ("baggage", "user.id=alice"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        // Local root: gets the baggage span tag.
        let root = SpanBuilder::from_name("test_baggage_root")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let _root_ctx = Context::current_with_span(root).attach();
        {
            // Child of an active local span -> not a local root -> must NOT get the baggage tag.
            let child = SpanBuilder::from_name("test_baggage_child")
                .with_kind(opentelemetry::trace::SpanKind::Internal)
                .start(&tracer);
            let _child_ctx = Context::current_with_span(child).attach();
        }
    })
    .await;
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;
use std::{collections::HashMap, ops::Deref, sync::Arc};

use datadog_opentelemetry::configuration::{
    Config, SamplingRuleConfig, TracePropagationBehaviorExtract, TracePropagationStyle,
};
use datadog_opentelemetry::log::LevelFilter;
use datadog_opentelemetry::make_test_tracer;
use opentelemetry::global::ObjectSafeSpan;
use opentelemetry::trace::{SpanBuilder, TraceContextExt, Tracer, TracerProvider};
use opentelemetry::Context;

use crate::integration_tests::{
    assert_subset, make_extractor, make_test_agent, with_test_agent_session,
};

// Verify the Datadog span processor exports only the spans the sampler keeps.
// opentelemetry 0.32 removed `SpanBuilder::with_sampling_result`, so a caller can no
// longer force the per-span decision; we drive it deterministically with sampling
// rules instead: a `sample_rate` of 0.0 -> drop -> `RecordOnly` (not exported) and a
// `sample_rate` of 1.0 -> keep -> `RecordAndSample` (exported). The snapshot must
// therefore contain only the kept span.
#[tokio::test]
async fn test_received_traces() {
    const SESSION_NAME: &str = "opentelemetry_api/test_received_traces";
    let mut cfg = Config::builder();
    cfg.set_trace_sampling_rules(vec![
        SamplingRuleConfig {
            resource: Some("kept-span".to_string()),
            sample_rate: 1.0,
            ..SamplingRuleConfig::default()
        },
        SamplingRuleConfig {
            resource: Some("dropped-span".to_string()),
            sample_rate: 0.0,
            ..SamplingRuleConfig::default()
        },
    ]);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, _, _| {
        let tracer = tracer_provider.tracer("test");

        // Dropped by the sampler (RecordOnly): must NOT be exported to the agent.
        drop(
            SpanBuilder::from_name("dropped-span")
                .with_kind(opentelemetry::trace::SpanKind::Client)
                .start_with_context(&tracer, &Context::new()),
        );

        // Kept by the sampler (RecordAndSample): must be exported to the agent.
        drop(
            SpanBuilder::from_name("kept-span")
                .with_kind(opentelemetry::trace::SpanKind::Client)
                .start_with_context(&tracer, &Context::new()),
        );
    })
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
/// Datadog and TraceContext headers carry the same 128-bit trace ID
/// (0x1111111111111111_0000000000000001). With Restart behavior a new trace is started and
/// the incoming context is referenced via a span link with
/// reason=propagation_behavior_extract, context_headers=datadog.
async fn test_injection_extraction_extract_behavior_restart_single_context() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_injection_extraction_extract_behavior_restart_single_context";
    let mut cfg = Config::builder();
    cfg.set_trace_propagation_behavior_extract(TracePropagationBehaviorExtract::Restart)
        .set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1"),
            ("x-datadog-parent-id", "1"),
            ("x-datadog-sampling-priority", "2"),
            ("x-datadog-tags", "_dd.p.tid=1111111111111111,_dd.p.dm=-4"),
            (
                "traceparent",
                "00-11111111111111110000000000000001-0000000000000001-01",
            ),
            ("tracestate", "dd=s:2;t.dm:-4,foo=1"),
            ("baggage", "key1=value1"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        let span = SpanBuilder::from_name("test_restart_single_context")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let new_trace_id_bytes = span.span_context().trace_id().to_bytes();
        let _ctx = Context::current_with_span(span).attach();

        let mut injected = HashMap::new();
        propagator.inject(&mut injected);

        // A fresh trace must be started: new trace ID must differ from the incoming one
        let original_trace_id_low: u64 = 1;
        let new_trace_id_low = u64::from_be_bytes(new_trace_id_bytes[8..16].try_into().unwrap());
        assert_ne!(
            new_trace_id_low, original_trace_id_low,
            "Restart behavior must start a new trace with a different trace ID"
        );
        assert_ne!(new_trace_id_low, 0, "New trace ID should be valid (not 0)");
        // Outbound headers must reflect the new trace ID
        assert_ne!(
            injected.get("x-datadog-trace-id").map(String::as_str),
            Some("1"),
            "Outbound trace ID should differ from the incoming trace ID"
        );
        // The original 128-bit trace high bits must not appear in the outbound tags
        if let Some(tags) = injected.get("x-datadog-tags") {
            assert!(
                !tags.contains("_dd.p.tid=1111111111111111"),
                "Outbound headers must not contain the original trace ID high bits"
            );
        }
        // Baggage is propagated in Restart mode
        assert_eq!(
            injected.get("baggage").map(String::as_str),
            Some("key1=value1"),
            "Baggage must be propagated in Restart mode"
        );
        // Restart makes its OWN sampling decision as a fresh local root: the sampler registers
        // brand-new propagation data for the restarted trace, so the upstream decision must not be
        // inherited. The incoming context carries priority=2 (USER_KEEP) and _dd.p.dm=-4 (manual);
        // the restarted trace must reflect neither.
        assert_ne!(
            injected.get("x-datadog-sampling-priority").map(String::as_str),
            Some("2"),
            "Restart must make its own sampling decision, not inherit the upstream priority (2)"
        );
        if let Some(tags) = injected.get("x-datadog-tags") {
            assert!(
                !tags.contains("_dd.p.dm=-4"),
                "Restarted trace must not inherit the upstream decision-maker (_dd.p.dm=-4), got: {tags}"
            );
            assert!(
                tags.contains("_dd.p.dm="),
                "Restarted trace must record its own sampling decision-maker tag, got: {tags}"
            );
        }
    })
    .await;
}

#[tokio::test]
/// Datadog and TraceContext headers reference different trace IDs. Restart mode creates a new
/// trace and a single span link to the primary (Datadog) context; terminated-context links for
/// the conflicting TraceContext are not included in the restarted trace context.
async fn test_injection_extraction_extract_behavior_restart_multiple_contexts() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_injection_extraction_extract_behavior_restart_multiple_contexts";
    let mut cfg = Config::builder();
    cfg.set_trace_propagation_behavior_extract(TracePropagationBehaviorExtract::Restart)
        .set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1"),
            ("x-datadog-parent-id", "1"),
            ("x-datadog-sampling-priority", "2"),
            ("x-datadog-tags", "_dd.p.tid=1111111111111111,_dd.p.dm=-4"),
            (
                "traceparent",
                "00-12345678901234567890123456789012-1234567890123456-01",
            ),
            ("baggage", "key1=value1"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        let span = SpanBuilder::from_name("test_restart_multiple_contexts")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let _ctx = Context::current_with_span(span).attach();

        let mut injected = HashMap::new();
        propagator.inject(&mut injected);

        // Outbound trace ID must differ from the incoming Datadog trace ID
        assert_ne!(
            injected.get("x-datadog-trace-id").map(String::as_str),
            Some("1"),
            "Outbound trace ID should differ from the incoming Datadog trace ID"
        );
        // Baggage is propagated in Restart mode
        assert_eq!(
            injected.get("baggage").map(String::as_str),
            Some("key1=value1"),
            "Baggage must be propagated in Restart mode"
        );
    })
    .await;
}

#[tokio::test]
/// Exercises the restart-detection branch in `DatadogSpanProcessor::on_start`. The local root span
/// is created from a context that carries `DatadogExtractData` but no active span, so it must get
/// the restart span link. The child span is created from a context that carries the SAME
/// `DatadogExtractData` AND an active span — `on_start` must take the "continue existing trace"
/// branch and add NO span link. Guards finding #3: `add_remote_links` must not fire when an active
/// span is present, even though the extract data is still in context.
async fn test_injection_extraction_extract_behavior_restart_child_not_relinked() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_injection_extraction_extract_behavior_restart_child_not_relinked";
    let mut cfg = Config::builder();
    cfg.set_trace_propagation_behavior_extract(TracePropagationBehaviorExtract::Restart)
        .set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1"),
            ("x-datadog-parent-id", "1"),
            ("x-datadog-sampling-priority", "2"),
            ("x-datadog-tags", "_dd.p.tid=1111111111111111,_dd.p.dm=-4"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        // Local root: extract data present, no active span -> restart branch -> gets the link.
        let root = SpanBuilder::from_name("test_restart_root")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let root_trace_id = root.span_context().trace_id();
        let _root_ctx = Context::current_with_span(root).attach();
        {
            // Child: extract data STILL in context, but now there is an active span -> continue
            // branch -> must NOT get a restart link.
            let child = SpanBuilder::from_name("test_restart_child")
                .with_kind(opentelemetry::trace::SpanKind::Internal)
                .start(&tracer);
            // Child must join the restarted trace, not start another one.
            assert_eq!(
                child.span_context().trace_id(),
                root_trace_id,
                "Child span must belong to the restarted trace"
            );
            let _child_ctx = Context::current_with_span(child).attach();
        }
    })
    .await;
}

#[tokio::test]
/// The entire incoming trace context is discarded. A new trace is started with no parent and
/// no span links. Baggage is also discarded.
async fn test_injection_extraction_extract_behavior_ignore() {
    const SESSION_NAME: &str =
        "opentelemetry_api/test_injection_extraction_extract_behavior_ignore";
    let mut cfg = Config::builder();
    cfg.set_trace_propagation_behavior_extract(TracePropagationBehaviorExtract::Ignore)
        .set_log_level_filter(LevelFilter::Debug);

    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, propagator, _| {
        let parent_ctx = propagator.extract(&make_extractor([
            ("x-datadog-trace-id", "1"),
            ("x-datadog-parent-id", "1"),
            ("x-datadog-sampling-priority", "2"),
            ("x-datadog-tags", "_dd.p.tid=1111111111111111,_dd.p.dm=-4"),
            (
                "traceparent",
                "00-11111111111111110000000000000001-0000000000000001-01",
            ),
            ("tracestate", "dd=s:2;t.dm:-4,foo=1"),
            ("baggage", "key1=value1"),
        ]));
        let _guard = parent_ctx.attach();

        let tracer = tracer_provider.tracer("test");
        let span = SpanBuilder::from_name("test_ignore")
            .with_kind(opentelemetry::trace::SpanKind::Server)
            .start(&tracer);
        let new_trace_id_bytes = span.span_context().trace_id().to_bytes();
        let _ctx = Context::current_with_span(span).attach();

        let mut injected = HashMap::new();
        propagator.inject(&mut injected);

        // A fresh trace must be started: new trace ID must differ from the incoming one
        let original_trace_id_low: u64 = 1;
        let new_trace_id_low = u64::from_be_bytes(new_trace_id_bytes[8..16].try_into().unwrap());
        assert_ne!(
            new_trace_id_low, original_trace_id_low,
            "Ignore behavior must start a new trace with a different trace ID"
        );
        // Outbound headers must reflect the new trace ID
        assert_ne!(
            injected.get("x-datadog-trace-id").map(String::as_str),
            Some("1"),
            "Outbound trace ID should differ from the incoming trace ID"
        );
        // Baggage is discarded in Ignore mode
        assert_eq!(
            injected.get("baggage"),
            None,
            "Baggage must not be propagated in Ignore mode"
        );
    })
    .await;
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
    const SESSION_NAME: &str = "opentelemetry_api/test_baggage_not_applied_to_non_local_root_child";
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

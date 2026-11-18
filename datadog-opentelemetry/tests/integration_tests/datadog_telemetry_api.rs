// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use datadog_opentelemetry::configuration::{Config, SamplingRuleConfig};
use datadog_opentelemetry::log::LevelFilter;
use datadog_opentelemetry::make_test_tracer;
use datadog_telemetry_api::{
    set_global, set_sampling_decision as set_sampling_decision_global, DatadogTelemetryApi,
    SamplingDecision,
};
use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{TraceContextExt, Tracer, TracerProvider},
};

use crate::integration_tests::{make_test_agent, with_test_agent_session};

#[tokio::test]
/// `SamplingDecision::Keep` and `SamplingDecision::Drop` set through the trait must be
/// reflected in outbound propagation headers as USER_KEEP (2) and USER_REJECT (-1). The
/// session snapshot additionally pins the exported Keep span (`_sampling_priority_v1`,
/// `_dd.p.dm`) and the client-side drop of the USER_REJECT trace.
async fn test_set_sampling_decision_updates_outbound_headers() {
    const SESSION_NAME: &str =
        "datadog_telemetry_api/test_set_sampling_decision_updates_outbound_headers";

    with_test_agent_session(
        SESSION_NAME,
        Config::builder(),
        |_, tracer_provider, propagator, telemetry, _| {
            let tracer = tracer_provider.tracer("datadog_telemetry_api_test");

            for (decision, expected_priority) in [
                (SamplingDecision::Keep, "2"),
                (SamplingDecision::Drop, "-1"),
            ] {
                let mut injected = HashMap::new();
                tracer.in_span("op", |cx| {
                    telemetry.set_sampling_decision(cx.span().span_context(), decision);
                    propagator.inject_context(&cx, &mut injected);
                });
                assert_eq!(
                    injected
                        .get("x-datadog-sampling-priority")
                        .map(String::as_str),
                    Some(expected_priority),
                    "the sampling decision must be propagated as priority {expected_priority}"
                );
            }
        },
    )
    .await;
}

#[tokio::test]
/// The free `set_sampling_decision` function must be a no-op while no global telemetry is
/// installed, and route to the instance installed by `set_global` afterwards.
/// These tests rely on nextest's per-test process isolation for the process-global state.
async fn test_set_sampling_decision_global() {
    const SESSION_NAME: &str = "datadog_telemetry_api/test_set_sampling_decision_global";
    let test_agent = make_test_agent(SESSION_NAME).await;
    let mut cfg = Config::builder();
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string());
    let components = make_test_tracer(Arc::new(cfg.build()));
    let tracer = components
        .tracer_provider
        .tracer("datadog_telemetry_api_test");

    let mut injected = HashMap::new();
    tracer.in_span("no_global", |cx| {
        set_sampling_decision_global(cx.span().span_context(), SamplingDecision::Keep);
        components.propagator.inject_context(&cx, &mut injected);
    });
    assert_eq!(
        injected
            .get("x-datadog-sampling-priority")
            .map(String::as_str),
        Some("1"),
        "without a global installed the decision must be ignored (AUTO_KEEP is propagated)"
    );

    set_global(components.datadog_telemetry);

    let mut injected = HashMap::new();
    tracer.in_span("with_global", |cx| {
        set_sampling_decision_global(cx.span().span_context(), SamplingDecision::Keep);
        components.propagator.inject_context(&cx, &mut injected);
    });
    assert_eq!(
        injected
            .get("x-datadog-sampling-priority")
            .map(String::as_str),
        Some("2"),
        "after set_global the decision must be applied (USER_KEEP is propagated)"
    );

    components
        .tracer_provider
        .shutdown()
        .expect("failed to shutdown");
}

#[tokio::test]
/// A trace rejected by the sampler and overridden with a manual keep must be exported with the
/// manual decision: USER_KEEP priority and the manual decision maker, and the sampler's
/// probability sampling rates (`_dd.rule_psr`, `_dd.agent_psr`, `_dd.limit_psr`) must be removed
/// from the root span, as they no longer describe how the trace was sampled.
async fn test_set_sampling_decision_exports_sampler_rejected_trace() {
    const SESSION_NAME: &str =
        "datadog_telemetry_api/test_set_sampling_decision_exports_sampler_rejected_trace";

    let test_agent = make_test_agent(SESSION_NAME).await;
    let mut cfg = Config::builder();
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string())
        // Rules drive the sampler deterministically per operation: `sampler_kept` is kept with
        // its rule rate attached, `sampler_rejected` and `manual_keep` are rejected, so the
        // manual override has sampler tags to remove. Note the rules match on `resource`,
        // which is the span name in the OTel mapping.
        .set_trace_sampling_rules(vec![
            SamplingRuleConfig {
                resource: Some("sampler_kept".to_string()),
                sample_rate: 1.0,
                ..SamplingRuleConfig::default()
            },
            SamplingRuleConfig {
                resource: Some("sampler_rejected".to_string()),
                sample_rate: 0.0,
                ..SamplingRuleConfig::default()
            },
            SamplingRuleConfig {
                resource: Some("manual_keep".to_string()),
                sample_rate: 0.0,
                ..SamplingRuleConfig::default()
            },
        ])
        .set_trace_rate_limit(10_000_000)
        .set_log_level_filter(LevelFilter::Debug);
    let components = make_test_tracer(Arc::new(cfg.build()));
    let tracer = components
        .tracer_provider
        .tracer("datadog_telemetry_api_test");

    // Control 1: a sampler-kept trace is exported with the rule rate attached.
    tracer.in_span("sampler_kept", |_| {});
    // Control 2: the sampler's rejection stands: the trace is dropped client-side.
    tracer.in_span("sampler_rejected", |_| {});
    // The manual keep overrides the sampler's rejection.
    tracer.in_span("manual_keep", |cx| {
        components
            .datadog_telemetry
            .set_sampling_decision(cx.span().span_context(), SamplingDecision::Keep);
    });

    components
        .tracer_provider
        .shutdown()
        .expect("failed to shutdown");

    let traces = test_agent.get_sent_traces().await;
    // The v0.4 payload names spans by their kind; the operation name is the `resource`.
    let spans_by_resource: HashMap<_, _> = traces
        .iter()
        .flat_map(|trace| trace.as_array().into_iter().flatten())
        .map(|span| (span["resource"].as_str().unwrap(), span))
        .collect();

    let sampler_kept = spans_by_resource
        .get("sampler_kept")
        .expect("the sampler-kept trace must be exported");
    assert_eq!(
        sampler_kept["metrics"]["_sampling_priority_v1"], 2.0,
        "the sampler-kept control trace must carry the rule's USER_KEEP"
    );
    assert_eq!(
        sampler_kept["meta"]["_dd.p.dm"], "-3",
        "the sampler-kept control trace must carry the rule mechanism"
    );
    assert_eq!(
        sampler_kept["metrics"]["_dd.rule_psr"], 1.0,
        "the sampler-kept control trace must carry the rule sampling rate, proving the sampler attaches it"
    );
    assert_eq!(
        sampler_kept["meta"]["_dd.p.ksr"], "1",
        "the sampler-kept control trace must carry the Knuth sample rate, proving the sampler attaches it"
    );

    assert!(
        !spans_by_resource.contains_key("sampler_rejected"),
        "the trace rejected by the sampler must not be exported without a manual override"
    );

    let manual_keep = spans_by_resource
        .get("manual_keep")
        .expect("the sampler-rejected trace marked as keep must be exported");
    assert_eq!(
        manual_keep["metrics"]["_sampling_priority_v1"], 2.0,
        "the manual keep must be exported as USER_KEEP"
    );
    assert_eq!(
        manual_keep["meta"]["_dd.p.dm"], "-4",
        "the manual keep must be exported with the manual mechanism"
    );
    for psr_key in ["_dd.rule_psr", "_dd.agent_psr", "_dd.limit_psr"] {
        assert_eq!(
            manual_keep["metrics"].get(psr_key),
            None,
            "the manual keep must not carry the sampler's `{psr_key}`"
        );
    }
    assert_eq!(
        manual_keep["meta"].get("_dd.p.ksr"),
        None,
        "the manual keep must not carry the sampler's stale Knuth sample rate"
    );

    // Pin the exported payloads, including the removed psr and Knuth rate keys, as a
    // regression snapshot.
    test_agent.assert_snapshot(SESSION_NAME).await;
}

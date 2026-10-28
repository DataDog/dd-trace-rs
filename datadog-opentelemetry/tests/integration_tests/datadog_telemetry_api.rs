// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use datadog_opentelemetry::{configuration::Config, make_test_tracer};
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
                    telemetry.set_sampling_decision(cx.span().span_context().clone(), decision);
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
        set_sampling_decision_global(cx.span().span_context().clone(), SamplingDecision::Keep);
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
        set_sampling_decision_global(cx.span().span_context().clone(), SamplingDecision::Keep);
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

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Integration coverage for telemetry shutdown against the *real* libdatadog
//! telemetry worker (not the `TestTelemetryHandle` used by the unit tests).
//!
//! Telemetry is a process-wide singleton, so these tests assume process
//! isolation between test cases (as provided by `cargo nextest`, which runs each
//! test in its own process). They assert shutdown *behaviour* — that it returns
//! cleanly and does not hang — rather than telemetry payload delivery, so they
//! stay robust regardless of ordering.

use std::{sync::Arc, time::Duration};

use datadog_opentelemetry::{configuration::Config, make_test_tracer};
use libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent;
use opentelemetry::{
    global,
    trace::{Tracer, TracerProvider as _},
};
use opentelemetry_sdk::trace::SdkTracerProvider;

use crate::integration_tests::make_test_agent;

/// Generous upper bound: a healthy shutdown is far quicker (OTel's default
/// shutdown timeout plus the 1s telemetry grace), but a real hang must fail the
/// test with a clear message instead of blocking until the CI harness kills it.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(30);

/// Runs `provider.shutdown()` (a blocking call) off the async worker thread and
/// fails if it errors or does not return within `SHUTDOWN_BOUND`.
async fn shutdown_within_bound(provider: SdkTracerProvider) {
    let handle = tokio::task::spawn_blocking(move || provider.shutdown());
    match tokio::time::timeout(SHUTDOWN_BOUND, handle).await {
        Err(_) => panic!("tracer_provider.shutdown() did not return within {SHUTDOWN_BOUND:?}"),
        Ok(join) => join
            .expect("shutdown task panicked")
            .expect("tracer_provider.shutdown() returned an error"),
    }
}

/// Spins up a test agent and builds a config pointed at it, asserting telemetry
/// is enabled (so the worker is actually exercised). The returned agent guard
/// must be kept alive for the duration of the test.
async fn config_for(session_name: &'static str) -> (Arc<Config>, DatadogTestAgent) {
    let test_agent = make_test_agent(session_name).await;
    let mut cfg = Config::builder();
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string());
    let cfg = Arc::new(cfg.build());
    assert!(
        cfg.telemetry_enabled(),
        "telemetry must default to enabled for these tests to exercise the worker"
    );
    (cfg, test_agent)
}

/// A local tracer (`make_test_tracer` / `init_local`) with a live telemetry
/// worker must shut down cleanly.
#[tokio::test]
async fn test_local_tracer_telemetry_shutdown_completes() {
    const SESSION_NAME: &str = "telemetry_shutdown/local";
    let (cfg, _agent) = config_for(SESSION_NAME).await;

    let (tracer_provider, _propagator) = make_test_tracer(cfg);
    tracer_provider
        .tracer("telemetry_shutdown_test")
        .in_span("op", |_| {});

    shutdown_within_bound(tracer_provider).await;
}

/// A global tracer (`tracing().init()`, which installs the provider into the
/// OTel globals) with a live telemetry worker must shut down cleanly.
#[tokio::test]
async fn test_global_tracer_telemetry_shutdown_completes() {
    const SESSION_NAME: &str = "telemetry_shutdown/global";
    let test_agent = make_test_agent(SESSION_NAME).await;
    let mut cfg = Config::builder();
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string());
    let cfg = cfg.build();
    assert!(cfg.telemetry_enabled());

    let tracer_provider = datadog_opentelemetry::tracing().with_config(cfg).init();
    global::tracer("telemetry_shutdown_test").in_span("op", |_| {});

    shutdown_within_bound(tracer_provider).await;
}

/// With several providers sharing the one process-global telemetry worker, only
/// the last shutdown stops it. Every shutdown must return cleanly: the earlier
/// ones because they are *not* the last user (fast path, worker stays up), the
/// final one because it drives the real `send_stop` + `wait_for_shutdown` path.
#[tokio::test]
async fn test_telemetry_shutdown_refcount_across_providers() {
    const SESSION_NAME: &str = "telemetry_shutdown/refcount";
    let (cfg, _agent) = config_for(SESSION_NAME).await;

    let (provider1, _) = make_test_tracer(cfg.clone());
    let (provider2, _) = make_test_tracer(cfg.clone());

    provider1
        .tracer("telemetry_shutdown_test")
        .in_span("op1", |_| {});
    provider2
        .tracer("telemetry_shutdown_test")
        .in_span("op2", |_| {});

    // Not the last user: must return promptly without stopping the shared worker.
    shutdown_within_bound(provider1).await;
    // Last user: stops the real worker and waits for it to drain.
    shutdown_within_bound(provider2).await;
}

/// Reusing the telemetry lifecycle within a process: build a tracer, shut it
/// down (which, as the last user, stops the process-global telemetry worker),
/// then build and use another tracer and shut it down too.
///
/// Telemetry is a non-restartable singleton, so the second tracer shares the
/// already-stopped worker — it does *not* get a fresh one. This test pins the
/// behaviour that matters: the reuse degrades gracefully. Building and exercising
/// the second tracer must not panic, its shutdown must not underflow the user
/// count or hang, and both shutdowns must return cleanly.
#[tokio::test]
async fn test_reuse_telemetry_lifecycle_after_shutdown_is_safe() {
    const SESSION_NAME: &str = "telemetry_shutdown/reuse";
    let (cfg, _agent) = config_for(SESSION_NAME).await;

    // First tracer: starts the global telemetry worker, stops it on shutdown.
    let (first_provider, _) = make_test_tracer(cfg.clone());
    first_provider
        .tracer("telemetry_shutdown_test")
        .in_span("op_before_shutdown", |_| {});
    shutdown_within_bound(first_provider).await;

    // Second tracer, built after the global worker was already stopped: registers
    // a telemetry user again and drives telemetry through span activity. Must stay
    // safe and shut down cleanly even though the underlying worker is not revived.
    let (second_provider, _) = make_test_tracer(cfg.clone());
    second_provider
        .tracer("telemetry_shutdown_test")
        .in_span("op_after_shutdown", |_| {});
    shutdown_within_bound(second_provider).await;
}

/// Stress the post-shutdown telemetry path. After the first iteration stops the
/// process-global worker, every later iteration registers a user, pushes span
/// activity (which feeds telemetry metrics) through the *stopped* handle, and
/// then stops it again. Across many cycles this must never panic, error, or hang
/// — guarding the "use a shutdown telemetry handle" path against regressions
/// (e.g. a stopped-handle call that starts to `unwrap`, or a cycle that leaks a
/// runtime and eventually errors).
#[tokio::test]
async fn test_post_shutdown_telemetry_use_is_panic_free_under_stress() {
    const SESSION_NAME: &str = "telemetry_shutdown/stress";
    const ITERATIONS: usize = 25;
    const SPANS_PER_ITERATION: usize = 8;

    let (cfg, _agent) = config_for(SESSION_NAME).await;

    for iteration in 0..ITERATIONS {
        let (provider, _) = make_test_tracer(cfg.clone());
        let tracer = provider.tracer("telemetry_shutdown_test");
        for span in 0..SPANS_PER_ITERATION {
            tracer.in_span(format!("iter{iteration}_span{span}"), |_| {});
        }
        shutdown_within_bound(provider).await;
    }
}

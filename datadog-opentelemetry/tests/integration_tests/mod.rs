// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{Hash, RandomState},
    sync::Arc,
};

use datadog_opentelemetry::{
    configuration::{Config, ConfigBuilder},
    make_test_tracer,
};
use libdd_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry_sdk::trace::SdkTracerProvider;

mod metrics;
mod opentelemetry_api;
mod tracing_api;

pub async fn with_test_agent_session(
    session_name: &'static str,
    mut cfg: ConfigBuilder,
    f: impl FnOnce(&mut DatadogTestAgent, SdkTracerProvider, Box<dyn TextMapPropagator>, Arc<Config>),
) {
    let mut test_agent = make_test_agent(session_name).await;
    cfg.set_trace_agent_url(test_agent.get_base_uri().await.to_string());
    let cfg = Arc::new(cfg.build());
    let (tracer_provider, propagator) = make_test_tracer(cfg.clone());
    f(
        &mut test_agent,
        tracer_provider.clone(),
        Box::new(propagator),
        cfg,
    );
    tracer_provider.shutdown().expect("failed to shutdown");
    test_agent.assert_snapshot(session_name).await;
}

pub async fn make_test_agent(session_name: &'static str) -> DatadogTestAgent {
    let relative_snapshot_path = "datadog-opentelemetry/tests/snapshots/";
    let test_agent = DatadogTestAgent::new(
        Some(relative_snapshot_path),
        None,
        &[
            ("SNAPSHOT_CI", "0"),
            (
                "SNAPSHOT_IGNORED_ATTRS",
                "span_id,trace_id,parent_id,duration,start,meta.otel.trace_id,metrics.busy_ns,metrics.idle_ns,metrics.thread.id,metrics.code.line.number,metrics.thread.id",
            ),
        ],
    )
    .await;
    test_agent.start_session(session_name, None).await;
    test_agent
}

fn make_extractor<I: IntoIterator<Item = (&'static str, &'static str)>>(
    headers: I,
) -> impl Extractor + Send + Sync {
    HashMap::<_, _, RandomState>::from_iter(
        headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
    )
}

#[track_caller]
fn assert_subset<I, S: IntoIterator<Item = I>, SS: IntoIterator<Item = I>>(set: S, subset: SS)
where
    I: Hash + Eq + fmt::Debug,
{
    let set: HashSet<_, RandomState> = HashSet::from_iter(set);
    for item in subset {
        if !set.contains(&item) {
            panic!("Set {set:?} does not contain subset item {item:?}");
        }
    }
}

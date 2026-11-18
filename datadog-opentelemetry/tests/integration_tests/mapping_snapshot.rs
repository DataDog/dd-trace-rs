// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Behavioral migration corpus for the OTel -> Datadog span conversion.
//!
//! Cases use the public OpenTelemetry pipeline and one test-agent session per scenario.
//! Snapshots protect the values that survive processor and writer overrides, not every
//! intermediate mapping result. In particular, processor sampling priority wins over
//! `sampling.priority`, and extracted Datadog tracestate is not SDK span tracestate.
//!
//! Missing snapshots fail before starting Docker. To deliberately generate new fixtures,
//! set `DD_MAPPING_GENERATE_SNAPSHOTS=1`. Review and commit both JSON files per case.

use std::time::Duration;

use datadog_opentelemetry::{
    configuration::{Config, ConfigBuilder},
    TracingComponents,
};
use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{SpanBuilder, SpanKind, TracerProvider},
    KeyValue,
};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};

use crate::integration_tests::{make_extractor, make_test_agent};

mod attributes;
mod configuration_chunks;
mod context_links;
mod fields;
mod naming;
mod status_events;

fn cases() -> impl Iterator<Item = &'static MappingCase> {
    [
        fields::CASES,
        naming::CASES,
        attributes::CASES,
        status_events::CASES,
        context_links::CASES,
        configuration_chunks::CASES,
    ]
    .into_iter()
    .flatten()
}

/// The shared agent helper creates missing files. Do not silently accept an absent oracle.
#[test]
// This switch controls fixture tooling, not tracer configuration.
#[allow(clippy::disallowed_methods)]
fn mapping_snapshot_fixtures_exist() {
    let generate = std::env::var_os("DD_MAPPING_GENERATE_SNAPSHOTS").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/opentelemetry_api/mapping");
    let mut names = std::collections::HashSet::new();
    for case in cases() {
        assert!(
            names.insert(case.name),
            "duplicate mapping case {}",
            case.name
        );
        for suffix in [".json", "_tracestats.json"] {
            let path = dir.join(format!("{}{suffix}", case.name));
            assert!(
                generate || path.is_file(),
                "missing snapshot {}",
                path.display()
            );
        }
    }
}

/// A single span case: one snapshot session, one mapping scenario.
struct MappingCase {
    /// Snapshot session name under `opentelemetry_api/mapping/`, `group__case`.
    name: &'static str,
    /// Tracer configuration for the case, `None` for the default configuration.
    configure: Option<fn(&mut ConfigBuilder)>,
    /// OTel resource of the case, `None` for the default resource.
    resource: Option<fn() -> Resource>,
    /// Emits the span(s) of the case through the OpenTelemetry API.
    run: fn(&SdkTracerProvider, &dyn TextMapPropagator),
}

/// A tracer provider (plus its propagator) shared by all cases that don't need their
/// own resource or configuration.
struct ProviderBundle {
    provider: SdkTracerProvider,
    propagator: Box<dyn TextMapPropagator>,
}

fn build_bundle(
    agent_uri: &str,
    configure: Option<fn(&mut ConfigBuilder)>,
    resource: Option<Resource>,
) -> ProviderBundle {
    let mut cfg = Config::builder();
    // Only `force_flush` delivers the queued traces: nothing is sent while the spans of
    // a case are being built, keeping each session to exactly its own case.
    cfg.set_trace_agent_url(agent_uri.to_string())
        .set_trace_writer_max_flush_interval(Duration::from_secs(1_000_000_000));
    if let Some(configure) = configure {
        configure(&mut cfg);
    }
    let builder = datadog_opentelemetry::tracing().with_config(cfg.build());
    let TracingComponents {
        tracer_provider,
        propagator,
        ..
    } = match resource {
        Some(resource) => builder.with_resource(resource).init_local(),
        None => builder.init_local(),
    };
    ProviderBundle {
        provider: tracer_provider,
        propagator: Box::new(propagator),
    }
}

/// Starts a span with the given name, kind and attributes, through the OpenTelemetry
/// API. The span ends when dropped.
fn start_span(
    provider: &SdkTracerProvider,
    name: &'static str,
    kind: SpanKind,
    attributes: Vec<KeyValue>,
) -> opentelemetry_sdk::trace::Span {
    SpanBuilder::from_name(name)
        .with_kind(kind)
        .with_attributes(attributes)
        .start(&provider.tracer("mapping"))
}

/// A case resource with the given attributes.
fn resource(attributes: Vec<KeyValue>) -> Resource {
    Resource::builder_empty()
        .with_attributes(attributes)
        .build()
}

fn emit(provider: &SdkTracerProvider, name: &str, kind: SpanKind, mut attrs: Vec<KeyValue>) {
    attrs.push(KeyValue::new("mapping.case", name.to_owned()));
    drop(
        SpanBuilder::from_name(name.to_owned())
            .with_kind(kind)
            .with_attributes(attrs)
            .start(&provider.tracer("mapping")),
    );
}

#[tokio::test]
async fn test_otel_to_datadog_mapping_paths() {
    mapping_snapshot_fixtures_exist();
    let test_agent = make_test_agent("opentelemetry_api/mapping").await;
    let agent_uri = test_agent.get_base_uri().await.to_string();

    let mut default_bundle: Option<ProviderBundle> = None;

    for case in cases() {
        let token = format!("opentelemetry_api/mapping/{}", case.name);
        // Starting the session clears anything the previous case left behind.
        test_agent.start_session(&token, None).await;

        let resource = case.resource.map(|make| make());
        let needs_own_provider = resource.is_some() || case.configure.is_some();
        let owned = needs_own_provider.then(|| build_bundle(&agent_uri, case.configure, resource));
        if default_bundle.is_none() {
            default_bundle = Some(build_bundle(&agent_uri, None, None));
        }
        let bundle = owned
            .as_ref()
            .unwrap_or_else(|| default_bundle.as_ref().unwrap());

        (case.run)(&bundle.provider, bundle.propagator.as_ref());
        bundle
            .provider
            .force_flush()
            .expect("failed to force flush the tracer provider");
        test_agent.assert_snapshot(&token).await;

        if let Some(bundle) = owned {
            bundle.provider.shutdown().expect("failed to shutdown");
        }
    }

    default_bundle
        .unwrap()
        .provider
        .shutdown()
        .expect("failed to shutdown the default tracer provider");
}

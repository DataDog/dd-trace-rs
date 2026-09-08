// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(windows))]
#[cfg_attr(miri, ignore)]
mod integration_tests;

#[test]
fn propagation_public_api_compatibility() {
    use std::{collections::HashMap, sync::Arc};

    use datadog_opentelemetry::{
        configuration::{Config, TracePropagationBehaviorExtract, TracePropagationStyle},
        propagation,
    };

    let style: TracePropagationStyle = propagation::TracePropagationStyle::Datadog;
    assert_eq!(style, TracePropagationStyle::Datadog);

    let behavior: TracePropagationBehaviorExtract =
        propagation::TracePropagationBehaviorExtract::Continue;
    assert_eq!(behavior, TracePropagationBehaviorExtract::Continue);

    let config = Arc::new(Config::builder().build());
    let _propagator: propagation::DatadogCompositePropagator<Config> =
        propagation::DatadogCompositePropagator::new(Arc::clone(&config));

    assert!(!propagation::config::get_extractors(config.as_ref()).is_empty());
    assert!(!propagation::config::get_injectors(config.as_ref()).is_empty());

    let headers = HashMap::<String, String>::new();
    let _ = propagation::baggage::extract_baggage(&headers);
    let _ = propagation::tracecontext::ot_extract_rv("rv:0000000000000001");
    let _ = propagation::tracecontext::ot_sanitize("rv:0000000000000001");
    let _ = propagation::tracecontext::ot_set_rv_th(None, None, None);
    let _ = propagation::context::InjectTraceState::from_header(String::new());

    let _ = propagation::b3::keys();
    let _ = propagation::b3multi::keys();
    let _ = propagation::datadog::keys();
    let _ = propagation::tracecontext::TRACEPARENT_KEY;
    let _ = propagation::baggage::BAGGAGE_KEY;
}

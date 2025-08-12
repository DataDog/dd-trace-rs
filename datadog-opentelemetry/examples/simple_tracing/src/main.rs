// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::Tracer;
use opentelemetry_sdk::trace::TracerProviderBuilder;

fn foo() {
    opentelemetry::global::tracer("foo").in_span("foo", |_cx| {
        println!("foo");
        bar()
    })
}

fn bar() {
    opentelemetry::global::tracer("bar").in_span("bar", |_cx| println!("bar"))
}

fn main() {
    let config = dd_trace::Config::builder()
        .set_service("simple_tracing".to_string())
        .build();

    let tracer_provider =
        datadog_opentelemetry::init_datadog(config, TracerProviderBuilder::default(), None);

    foo();

    tracer_provider.shutdown().expect("tracer shutdown failed");
}

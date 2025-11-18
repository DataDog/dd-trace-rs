// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::Tracer;

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
    let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::core::Config::builder()
                .set_service("simple_tracing".to_string())
                .build(),
        )
        .init();

    foo();

    tracer_provider.shutdown().expect("tracer shutdown failed");
}

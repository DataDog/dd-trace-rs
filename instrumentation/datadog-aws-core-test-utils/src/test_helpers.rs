// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::global;
use opentelemetry::propagation::text_map_propagator::FieldIter;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::Context;

/// Propagation field used by tests to assert that context injection ran.
pub const TEST_CONTEXT_INJECTED_KEY: &str = "test_context_injected";

#[derive(Debug)]
struct TestContext;

/// Installs the test text map propagator as the global OpenTelemetry propagator.
pub fn ensure_test_propagator() {
    global::set_text_map_propagator(TestTextMapPropagator::new());
}

/// Returns an OpenTelemetry context that the test propagator will inject.
pub fn test_context() -> Context {
    Context::new().with_value(TestContext)
}

/// Text map propagator that records whether a test context was injected.
#[derive(Debug)]
pub struct TestTextMapPropagator {
    fields: Vec<String>,
}

impl TestTextMapPropagator {
    /// Creates a test propagator with the single injected-context field.
    pub fn new() -> Self {
        Self {
            fields: vec![TEST_CONTEXT_INJECTED_KEY.to_string()],
        }
    }
}

impl Default for TestTextMapPropagator {
    fn default() -> Self {
        Self::new()
    }
}

impl TextMapPropagator for TestTextMapPropagator {
    fn inject_context(&self, cx: &Context, injector: &mut dyn Injector) {
        if cx.get::<TestContext>().is_none() {
            return;
        }

        injector.set(TEST_CONTEXT_INJECTED_KEY, "true".to_string());
    }

    fn extract_with_context(&self, cx: &Context, extractor: &dyn Extractor) -> Context {
        if extractor.get(TEST_CONTEXT_INJECTED_KEY) == Some("true") {
            cx.clone().with_value(TestContext)
        } else {
            cx.clone()
        }
    }

    fn fields(&self) -> FieldIter<'_> {
        FieldIter::new(&self.fields)
    }
}

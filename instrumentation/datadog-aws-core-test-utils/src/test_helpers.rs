// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::propagation::text_map_propagator::FieldIter;
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry::Context;

pub const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
pub const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
pub const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";

#[derive(Debug)]
pub struct FixedTextMapTestPropagator {
    fields: Vec<String>,
}

impl FixedTextMapTestPropagator {
    pub fn new() -> Self {
        Self {
            fields: vec![
                DATADOG_TRACE_ID_KEY.to_string(),
                DATADOG_PARENT_ID_KEY.to_string(),
                DATADOG_SAMPLING_PRIORITY_KEY.to_string(),
            ],
        }
    }
}

impl Default for FixedTextMapTestPropagator {
    fn default() -> Self {
        Self::new()
    }
}

impl TextMapPropagator for FixedTextMapTestPropagator {
    fn inject_context(&self, _cx: &Context, injector: &mut dyn Injector) {
        injector.set(DATADOG_TRACE_ID_KEY, "123456789".to_string());
        injector.set(DATADOG_PARENT_ID_KEY, "987654321".to_string());
        injector.set(DATADOG_SAMPLING_PRIORITY_KEY, "1".to_string());
    }

    fn extract_with_context(&self, cx: &Context, _extractor: &dyn Extractor) -> Context {
        cx.clone()
    }

    fn fields(&self) -> FieldIter<'_> {
        FieldIter::new(&self.fields)
    }
}

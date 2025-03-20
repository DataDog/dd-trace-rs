// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{text_map_propagator::TRACESTATE_KEY, trace_propagation_style::TracePropagationStyle};

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Sampling {
    pub priority: Option<i8>,
    pub mechanism: Option<u8>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanLink {
    pub trace_id: u64,
    pub trace_id_high: Option<u64>,
    pub span_id: u64,
    pub attributes: Option<HashMap<String, String>>,
    pub tracestate: Option<String>,
    pub flags: Option<u32>,
}

impl SpanLink {
    pub fn terminated_context(context: &SpanContext, style: TracePropagationStyle) -> Self {
        let flags = context
            .sampling
            .and_then(|sampling| sampling.priority)
            .map(|priority| u32::from(priority > 0));

        let tracestate: Option<String> = match style {
            TracePropagationStyle::TraceContext => context.tags.get(TRACESTATE_KEY).cloned(),
            _ => None,
        };

        let attributes = Some(HashMap::from([
            ("reason".to_string(), "terminated_context".to_string()),
            ("context_headers".to_string(), style.to_string()),
        ]));

        let (trace_id_high, trace_id) = Self::split_trace_id(context.trace_id);

        SpanLink {
            trace_id,
            trace_id_high,
            span_id: context.span_id,
            attributes,
            tracestate,
            flags,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn split_trace_id(trace_id: u128) -> (Option<u64>, u64) {
        let trace_id_lower_order_bits = trace_id as u64;

        let higher = (trace_id >> 64) as u64;
        let trace_id_higher_order_bits = if higher > 0 { Some(higher) } else { None };

        (trace_id_higher_order_bits, trace_id_lower_order_bits)
    }
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanContext {
    pub trace_id: u128,
    pub span_id: u64,
    pub sampling: Option<Sampling>,
    pub origin: Option<String>,
    pub tags: HashMap<String, String>,
    pub links: Vec<SpanLink>,
}

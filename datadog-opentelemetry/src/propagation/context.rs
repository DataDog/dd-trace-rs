// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Span context types for trace propagation.
//!
//! This module provides types representing span context information that is
//! propagated across service boundaries, including trace IDs, span IDs,
//! sampling decisions, and W3C tracestate data.

use std::collections::HashMap;

pub use super::tracecontext::{InjectTraceState, Tracestate};
use crate::core::{
    configuration::TracePropagationStyle,
    sampling::{SamplingMechanism, SamplingPriority},
};

use super::tracecontext::TRACESTATE_KEY;

pub(super) const DATADOG_PROPAGATION_TAG_PREFIX: &str = "_dd.p.";

/// Sampling information extracted from or to be injected into trace context.
#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Sampling {
    /// The sampling priority indicating whether the trace should be kept or rejected.
    pub priority: Option<SamplingPriority>,
    /// The mechanism that made the sampling decision.
    pub mechanism: Option<SamplingMechanism>,
}

/// A link to another span, used to represent causal relationships between spans.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanLink {
    /// Lower 64 bits of the linked trace ID.
    pub trace_id: u64,
    /// Upper 64 bits of the linked trace ID (for 128-bit trace IDs).
    pub trace_id_high: Option<u64>,
    /// The linked span ID.
    pub span_id: u64,
    /// Additional attributes associated with the link.
    pub attributes: Option<HashMap<String, String>>,
    /// W3C tracestate header value from the linked context.
    pub tracestate: Option<String>,
    /// Trace flags from the linked context.
    pub flags: Option<u32>,
}

impl SpanLink {
    /// Creates a span link for a restarted context scenario.
    pub(crate) fn restart(context: &SpanContext, style: TracePropagationStyle) -> Self {
        let attributes = Some(HashMap::from([
            (
                "reason".to_string(),
                "propagation_behavior_extract".to_string(),
            ),
            ("context_headers".to_string(), style.to_string()),
        ]));

        SpanLink::new(context, style, attributes)
    }
    /// Creates a span link for a terminated context scenario.
    pub(super) fn terminated_context(context: &SpanContext, style: TracePropagationStyle) -> Self {
        let attributes = Some(HashMap::from([
            ("reason".to_string(), "terminated_context".to_string()),
            ("context_headers".to_string(), style.to_string()),
        ]));

        SpanLink::new(context, style, attributes)
    }

    /// Creates a new span link from a span context.
    pub(super) fn new(
        context: &SpanContext,
        style: TracePropagationStyle,
        attributes: Option<HashMap<String, String>>,
    ) -> Self {
        let (trace_id_high, trace_id) = split_trace_id(context.trace_id);

        let tracestate: Option<String> = match style {
            TracePropagationStyle::TraceContext => context.tags.get(TRACESTATE_KEY).cloned(),
            _ => None,
        };

        let flags = context
            .sampling
            .priority
            .map(|priority| u32::from(priority.is_keep()));

        SpanLink {
            trace_id,
            trace_id_high,
            span_id: context.span_id,
            attributes,
            tracestate,
            flags,
        }
    }
}

/// Span context data prepared for injection into outgoing requests.
///
/// This is a borrowed view of span context optimized for the injection process,
/// avoiding unnecessary clones during propagation.
pub struct InjectSpanContext<'a> {
    /// The 128-bit trace identifier.
    pub trace_id: u128,
    /// The 64-bit span identifier.
    pub span_id: u64,
    /// Sampling information for this trace.
    pub sampling: Sampling,
    /// The origin of the trace (e.g., "synthetics", "rum").
    pub origin: Option<&'a str>,
    /// Propagation tags (mutable to allow adding error metadata).
    pub tags: &'a mut HashMap<String, String>,
    /// Whether this context was received from a remote service.
    pub is_remote: bool,
    /// W3C tracestate data to inject.
    pub tracestate: Option<InjectTraceState>,
}

#[cfg(test)]
/// A helper function because creating synthetic borrowed data is a bit harder
/// than owned data
pub(crate) fn span_context_to_inject(c: &mut SpanContext) -> InjectSpanContext<'_> {
    InjectSpanContext {
        trace_id: c.trace_id,
        span_id: c.span_id,
        sampling: c.sampling,
        origin: c.origin.as_deref(),
        tags: &mut c.tags,
        is_remote: c.is_remote,
        tracestate: c.tracestate.as_ref().map(|ts| {
            InjectTraceState::from_header(ts.additional_values.as_ref().map_or(
                String::new(),
                |v| {
                    v.iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(",")
                },
            ))
        }),
    }
}

/// Context information for a span that can be propagated across service boundaries.
///
/// Contains trace identification, sampling decisions, and propagation metadata.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanContext {
    /// The 128-bit trace identifier.
    pub trace_id: u128,
    /// The 64-bit span identifier.
    pub span_id: u64,
    /// Sampling information for this trace.
    pub sampling: Sampling,
    /// The origin of the trace (e.g., "synthetics", "rum").
    pub origin: Option<String>,
    /// Propagation tags (prefixed with `_dd.p.`).
    pub tags: HashMap<String, String>,
    /// Links to related spans.
    pub links: Vec<SpanLink>,
    /// Whether this context was received from a remote service.
    pub is_remote: bool,
    /// W3C tracestate information.
    pub tracestate: Option<Tracestate>,
}

pub(crate) fn split_trace_id(trace_id: u128) -> (Option<u64>, u64) {
    let trace_id_lower_order_bits = trace_id as u64;

    let higher = (trace_id >> 64) as u64;
    let trace_id_higher_order_bits = if higher > 0 { Some(higher) } else { None };

    (trace_id_higher_order_bits, trace_id_lower_order_bits)
}

pub(crate) fn combine_trace_id(trace_id: u64, higher_bits_hex: Option<&String>) -> u128 {
    if let Some(combined_trace_id) = higher_bits_hex
        .and_then(|higher| u64::from_str_radix(higher, 16).ok())
        .map(|higher| {
            let higher = higher as u128;
            (higher << 64) + (trace_id as u128)
        })
    {
        combined_trace_id
    } else {
        trace_id as u128
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::core::sampling::priority;

    use crate::propagation::context::{combine_trace_id, split_trace_id, SamplingPriority};

    use super::Tracestate;

    #[test]
    fn test_combine() {
        let trace_id = u128::MAX;

        let (higher, lower) = split_trace_id(trace_id);

        let higher_hex = format!("{:016x}", higher.unwrap());

        let combined = combine_trace_id(lower, Some(&higher_hex));

        assert_eq!(trace_id, combined)
    }

    #[test]
    fn test_valid_tracestate_no_key() {
        let tracestate = Tracestate::from_str("foo=1,=2,=4").expect("parsed tracesate");

        assert_eq!(
            tracestate.additional_values,
            Some(vec![
                ("foo".to_string(), "1".to_string()),
                ("".to_string(), "2".to_string()),
                ("".to_string(), "4".to_string())
            ])
        )
    }

    #[test]
    fn test_invalid_tracestate_no_value() {
        assert!(Tracestate::from_str("foo=1,2").is_err());
    }

    #[test]
    fn test_invalid_tracestate_empty_kvp() {
        assert!(Tracestate::from_str("foo=1,,,").is_err());
    }

    #[test]
    fn test_invalid_tracestate_multiple_eq_value() {
        assert!(Tracestate::from_str("foo=1,bar=2=2").is_err());
    }

    #[test]
    fn test_valid_tracestate_non_ascii_char_in_value() {
        assert!(Tracestate::from_str("foo=öï,bar=2").is_ok())
    }

    #[test]
    fn test_invalid_tracestate_non_ascii_char_in_key() {
        assert!(Tracestate::from_str("föö=oi,bar=2").is_err())
    }

    #[test]
    fn test_invalid_tracestate_non_ascii_char_with_tabs() {
        assert!(Tracestate::from_str("foo=\t öï  \t\t ").is_ok())
    }

    #[test]
    fn test_valid_tracestate_ascii_char_with_tabs() {
        let tracestate = Tracestate::from_str("foo=\t valid  \t\t ").expect("parsed tracestate");

        assert_eq!(
            tracestate.additional_values,
            Some(vec![("foo".to_string(), "\t valid  \t\t ".to_string()),])
        )
    }

    #[test]
    fn test_valid_tracestate_dd_ascii_char_with_tabs() {
        let tracestate = Tracestate::from_str("dd=\t  o:valid  \t\t ").expect("parsed tracestate");

        assert_eq!(tracestate.origin, Some("valid".to_string()))
    }

    #[test]
    fn test_valid_tracestate_dd_non_ascii_char_with_tabs() {
        assert!(Tracestate::from_str("dd=o:välïd  \t\t ").is_ok())
    }

    #[test]
    fn test_malformed_tracestate_dd_ascii_char_with_tabs() {
        let tracestate =
            Tracestate::from_str("dd=\t  o:valid;;s:1; \t").expect("parsed tracestate");

        assert_eq!(tracestate.origin, Some("valid".to_string()))
    }

    #[test]
    fn test_sampling_priority() {
        assert_eq!(
            SamplingPriority::from_str("-5").unwrap(),
            SamplingPriority::from_i8(-5)
        );

        assert_eq!(
            SamplingPriority::from_str("-1").unwrap(),
            priority::USER_REJECT
        );

        assert_eq!(
            SamplingPriority::from_str("1").unwrap(),
            priority::AUTO_KEEP
        );

        assert!(SamplingPriority::from_str("-12345678901234567890").is_err());

        assert!(!SamplingPriority::from_i8(-42).is_keep());

        assert!(SamplingPriority::from_i8(42).is_keep());

        let prio = SamplingPriority::from_i8(42).into_i8();
        assert_eq!(prio, 42);

        let prio = priority::USER_KEEP.into_i8();
        assert_eq!(prio, 2);
    }
}

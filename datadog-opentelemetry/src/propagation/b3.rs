// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! B3 single-header trace context propagation.
//!
//! Implements the [B3 single-header propagation format] used by Zipkin and
//! compatible tracers. A single `b3` header carries the trace id, span id,
//! sampling state, and an optional (ignored) parent span id, separated by
//! `-`.
//!
//! Behavior matches the Python tracer's `_B3SingleHeader` so wire-level
//! semantics stay aligned with the other Datadog tracers. In particular,
//! sampling-only forms (`b3: 0`, `b3: 1`, `b3: d`) are preserved: the
//! returned [`SpanContext`] carries a zero trace id and the upstream
//! sampling decision so callers can honor the upstream accept/deny/debug
//! intent rather than fall back to local sampling policy.
//!
//! [B3 single-header propagation format]: https://github.com/openzipkin/b3-propagation#single-header

use std::sync::LazyLock;

use crate::core::sampling::{priority, SamplingPriority};
use crate::dd_warn;
use crate::propagation::{
    carrier::{Extractor, Injector},
    context::{InjectSpanContext, Sampling, SpanContext},
};

/// B3 single-header name.
pub const B3_SINGLE_KEY: &str = "b3";

static B3_SINGLE_HEADER_KEYS: LazyLock<[String; 1]> = LazyLock::new(|| [B3_SINGLE_KEY.to_owned()]);

/// Extract trace context from a carrier using the `b3` single header.
///
/// The header is parsed as `{trace_id}-{span_id}-{sampling_state}-{parent_span_id}`,
/// with the trailing fields optional. Returns `None` when:
///
/// - the header is missing or empty;
/// - the trace-and-span form is present but the trace id is malformed or zero;
/// - the span id is present but malformed (a missing or zero span id is accepted and recorded as
///   `0`);
/// - the sampling-only form is present but the sampling value is unknown.
///
/// The sampling-only forms `b3: 0`, `b3: 1`, and `b3: d` are preserved as a
/// context with `trace_id = 0`, `span_id = 0`, and the parsed priority, so
/// the upstream sampling decision survives even when no trace ids were sent.
pub fn extract(carrier: &dyn Extractor) -> Option<SpanContext> {
    let header = carrier.get(B3_SINGLE_KEY)?;
    if header.is_empty() {
        return None;
    }

    let mut parts = header.split('-');
    let first = parts.next();
    let second = parts.next();
    let third = parts.next();
    // Any trailing parent span id is ignored per the B3 spec.

    let (trace_id, span_id, priority): (u128, u64, Option<SamplingPriority>) =
        match (first, second, third) {
            // Sampling-only form: a single segment is the sampling state.
            // An unknown sampling token (anything but `0`/`1`/`d`) makes the
            // whole header useless — bail out.
            (Some(s), None, None) => (0, 0, Some(parse_priority(s)?)),
            (Some(t), Some(s), sampled) => {
                let trace_id = parse_trace_id(t)?;
                let span_id = parse_span_id(s)?;
                let priority = sampled.and_then(parse_priority);
                (trace_id, span_id, priority)
            }
            // `split` always yields at least one element, so this branch is unreachable.
            _ => return None,
        };

    Some(SpanContext {
        trace_id,
        span_id,
        sampling: Sampling {
            priority,
            mechanism: None,
        },
        origin: None,
        tags: std::collections::HashMap::new(),
        links: Vec::new(),
        is_remote: true,
        tracestate: None,
    })
}

/// Inject trace context into a carrier as a `b3` single header.
pub fn inject(context: &InjectSpanContext, carrier: &mut dyn Injector) {
    let trace_id = format_b3_trace_id(context.trace_id);
    let mut header = format!("{trace_id}-{:016x}", context.span_id);
    if let Some(priority) = context.sampling.priority {
        let p = priority.into_i8();
        if p <= 0 {
            header.push_str("-0");
        } else if p == 1 {
            header.push_str("-1");
        } else {
            header.push_str("-d");
        }
    }
    carrier.set(B3_SINGLE_KEY, header);
}

/// Returns the header keys used by B3 single-header propagation.
pub fn keys() -> &'static [String] {
    B3_SINGLE_HEADER_KEYS.as_slice()
}

fn parse_trace_id(hex: &str) -> Option<u128> {
    let id = match u128::from_str_radix(hex, 16) {
        Ok(id) => id,
        Err(e) => {
            dd_warn!("Propagator (b3): malformed trace_id {hex:?}: {e}");
            return None;
        }
    };
    if id == 0 {
        return None;
    }
    Some(id)
}

/// Parses a B3 span id. Returns `None` only on hex-parse failure; an
/// explicit `0` is accepted so callers can distinguish "malformed → reject
/// the whole context" from "zero / no parent → accept with span_id 0".
fn parse_span_id(hex: &str) -> Option<u64> {
    match u64::from_str_radix(hex, 16) {
        Ok(id) => Some(id),
        Err(e) => {
            dd_warn!("Propagator (b3): malformed span_id {hex:?}: {e}");
            None
        }
    }
}

fn parse_priority(sampled: &str) -> Option<SamplingPriority> {
    match sampled {
        "0" => Some(priority::AUTO_REJECT),
        "1" => Some(priority::AUTO_KEEP),
        "d" => Some(priority::USER_KEEP),
        _ => None,
    }
}

fn format_b3_trace_id(trace_id: u128) -> String {
    if trace_id > u64::MAX as u128 {
        format!("{trace_id:032x}")
    } else {
        format!("{trace_id:016x}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::collections::HashMap;

    use crate::core::configuration::{Config, TracePropagationStyle};
    use crate::core::sampling::priority;
    use crate::propagation::{context::span_context_to_inject, Propagator};

    use super::*;

    fn carrier_with(header: &str) -> HashMap<String, String> {
        HashMap::from([("b3".to_string(), header.to_string())])
    }

    #[test]
    fn extract_missing_header_returns_none() {
        let carrier: HashMap<String, String> = HashMap::new();
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_empty_header_returns_none() {
        let carrier = carrier_with("");
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_sampling_only_forms_preserve_upstream_decision() {
        // Sampling-only `b3: 0/1/d` carries no trace ids but does carry an
        // explicit upstream sampling decision; the propagator returns a
        // zero-trace context so the sampler can honor that decision.
        let ctx0 = extract(&carrier_with("0")).unwrap();
        assert_eq!(ctx0.trace_id, 0);
        assert_eq!(ctx0.span_id, 0);
        assert_eq!(ctx0.sampling.priority, Some(priority::AUTO_REJECT));

        let ctx1 = extract(&carrier_with("1")).unwrap();
        assert_eq!(ctx1.sampling.priority, Some(priority::AUTO_KEEP));

        let ctxd = extract(&carrier_with("d")).unwrap();
        assert_eq!(ctxd.sampling.priority, Some(priority::USER_KEEP));
    }

    #[test]
    fn extract_sampling_only_unknown_value_returns_none() {
        // A single-segment header with an unknown sampling token gives us
        // neither ids nor a usable sampling decision — drop it entirely.
        assert_eq!(extract(&carrier_with("xyz")), None);
    }

    #[test]
    fn extract_malformed_span_id_rejects_context() {
        // A valid trace id paired with a garbage span id rejects the whole
        // context — silently coercing to span_id 0 could let a bogus b3
        // context override later, valid propagation headers.
        assert_eq!(extract(&carrier_with("80f198ee56343ba8-nothex-1")), None);
    }

    #[test]
    fn extract_two_part_form_has_no_sampling() {
        let ctx = extract(&carrier_with("80f198ee56343ba8-00f067aa0ba902b7")).unwrap();
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8);
        assert_eq!(ctx.span_id, 0x00f0_67aa_0ba9_02b7);
        assert_eq!(ctx.sampling.priority, None);
        assert!(ctx.is_remote);
    }

    #[test]
    fn extract_three_part_form_parses_sampling() {
        let ctx = extract(&carrier_with("80f198ee56343ba8-00f067aa0ba902b7-1")).unwrap();
        assert_eq!(ctx.sampling.priority, Some(priority::AUTO_KEEP));
    }

    #[test]
    fn extract_four_part_form_ignores_parent_span_id() {
        let ctx = extract(&carrier_with(
            "80f198ee56343ba8-00f067aa0ba902b7-0-05e3ac9a4f6e3b90",
        ))
        .unwrap();
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8);
        assert_eq!(ctx.span_id, 0x00f0_67aa_0ba9_02b7);
        assert_eq!(ctx.sampling.priority, Some(priority::AUTO_REJECT));
    }

    #[test]
    fn extract_128_bit_trace_id() {
        let ctx = extract(&carrier_with(
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-d",
        ))
        .unwrap();
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8_64fe_8b2a_57d3_eff7u128);
        assert_eq!(ctx.span_id, 0xe457_b5a2_e4d8_6bd1);
        assert_eq!(ctx.sampling.priority, Some(priority::USER_KEEP));
    }

    #[test]
    fn extract_zero_trace_id_returns_none() {
        assert_eq!(extract(&carrier_with("0000000000000000-1-1")), None);
    }

    #[test]
    fn extract_malformed_trace_id_returns_none() {
        assert_eq!(extract(&carrier_with("nothex-1-1")), None);
    }

    #[test]
    fn extract_unknown_sampling_value_defers_priority() {
        let ctx = extract(&carrier_with("80f198ee56343ba8-1-xyz")).unwrap();
        assert_eq!(ctx.sampling.priority, None);
    }

    #[test]
    fn extract_zero_span_id_yields_zero() {
        let ctx = extract(&carrier_with("80f198ee56343ba8-0000000000000000-1")).unwrap();
        assert_eq!(ctx.span_id, 0);
    }

    #[test]
    fn inject_no_priority_omits_sampling_segment() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8,
            span_id: 0x00f0_67aa_0ba9_02b7,
            sampling: Sampling {
                priority: None,
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier["b3"], "80f198ee56343ba8-00f067aa0ba902b7");
    }

    #[test]
    fn inject_auto_keep_appends_one() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8,
            span_id: 0x00f0_67aa_0ba9_02b7,
            sampling: Sampling {
                priority: Some(priority::AUTO_KEEP),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier["b3"], "80f198ee56343ba8-00f067aa0ba902b7-1");
    }

    #[test]
    fn inject_auto_reject_appends_zero() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8,
            span_id: 0x00f0_67aa_0ba9_02b7,
            sampling: Sampling {
                priority: Some(priority::AUTO_REJECT),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier["b3"], "80f198ee56343ba8-00f067aa0ba902b7-0");
    }

    #[test]
    fn inject_user_keep_appends_debug() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8,
            span_id: 0x00f0_67aa_0ba9_02b7,
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier["b3"], "80f198ee56343ba8-00f067aa0ba902b7-d");
    }

    #[test]
    fn inject_128_bit_trace_id_emits_32_hex() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8_64fe_8b2a_57d3_eff7u128,
            span_id: 0xe457_b5a2_e4d8_6bd1,
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(
            carrier["b3"],
            "80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-d"
        );
    }

    #[test]
    fn propagator_dispatch_routes_to_b3_single() {
        let carrier = carrier_with("80f198ee56343ba8-00f067aa0ba902b7-1");
        let propagator = TracePropagationStyle::B3SingleHeader;
        let ctx = propagator
            .extract(&carrier, &Config::builder().build())
            .expect("b3 single-header dispatch should produce context");
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8);
    }

    #[test]
    fn propagator_dispatch_exposes_keys() {
        let propagator = TracePropagationStyle::B3SingleHeader;
        let k: &[String] = <TracePropagationStyle as Propagator<Config>>::keys(&propagator);
        assert_eq!(k, &["b3".to_string()]);
    }
}

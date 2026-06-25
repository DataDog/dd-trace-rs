// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! B3 multi-header trace context propagation.
//!
//! Implements the [B3 multiple-header propagation format] used by Zipkin and
//! compatible tracers. Trace and span ids are exchanged via separate headers,
//! with sampling expressed through `X-B3-Sampled` (accept/deny) or
//! `X-B3-Flags` (debug ≡ keep).
//!
//! Behavior matches the Python tracer's `_B3MultiHeader` so that traces
//! propagated through a Datadog-rust process keep the same wire-level
//! semantics as the other Datadog tracers.
//!
//! [B3 multiple-header propagation format]: https://github.com/openzipkin/b3-propagation#multiple-headers

use std::sync::LazyLock;

use crate::core::sampling::{priority, SamplingPriority};
use crate::dd_warn;
use crate::propagation::{
    carrier::{Extractor, Injector},
    context::{InjectSpanContext, Sampling, SpanContext},
};

/// B3 trace ID header. Lower-hex, 16 or 32 chars.
pub const B3_TRACE_ID_KEY: &str = "x-b3-traceid";
/// B3 span ID header. Lower-hex, 16 chars.
pub const B3_SPAN_ID_KEY: &str = "x-b3-spanid";
/// B3 sampled header. `0` = deny, `1` = accept; any other value defers.
pub const B3_SAMPLED_KEY: &str = "x-b3-sampled";
/// B3 flags header. `1` = debug (treated as keep with highest priority).
pub const B3_FLAGS_KEY: &str = "x-b3-flags";

static B3_HEADER_KEYS: LazyLock<[String; 4]> = LazyLock::new(|| {
    [
        B3_TRACE_ID_KEY.to_owned(),
        B3_SPAN_ID_KEY.to_owned(),
        B3_SAMPLED_KEY.to_owned(),
        B3_FLAGS_KEY.to_owned(),
    ]
});

/// Extract trace context from a carrier using B3 multi-headers.
///
/// Returns `None` when the carrier lacks a `x-b3-traceid` header, the trace
/// id cannot be parsed as a non-zero hex integer, or a present span id
/// header is malformed. A missing or zero span id is accepted and recorded
/// as `0`, matching how the Datadog propagator handles missing parent ids.
///
/// Sampling-only requests (only `x-b3-sampled` / `x-b3-flags` present, no
/// `x-b3-traceid`) drop here. This matches dd-trace-py's `_B3MultiHeader`
/// but diverges from dd-trace-java, which preserves the sampling state in
/// the same way it does for the single-header form. Java is the more
/// spec-correct side (the B3 spec allows `X-B3-Sampled` to stand alone).
/// Aligning with java is tracked in APMSP-3579 alongside the cross-language
/// system-tests; it is blocked on APMSP-3578 (resolve_contexts zero-trace
/// primary fix) because the change widens that bug's surface area.
pub fn extract(carrier: &dyn Extractor) -> Option<SpanContext> {
    let trace_id_hex = carrier.get(B3_TRACE_ID_KEY)?;
    let trace_id = parse_trace_id(trace_id_hex)?;

    let span_id = match carrier.get(B3_SPAN_ID_KEY) {
        Some(hex) => parse_span_id(hex)?,
        None => 0,
    };

    let priority = extract_priority(carrier);

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

/// Inject trace context into a carrier using B3 multi-headers.
pub fn inject(context: &InjectSpanContext, carrier: &mut dyn Injector) {
    carrier.set(B3_TRACE_ID_KEY, format_b3_trace_id(context.trace_id));
    carrier.set(B3_SPAN_ID_KEY, format!("{:016x}", context.span_id));

    let Some(priority) = context.sampling.priority else {
        return;
    };
    let p = priority.into_i8();
    if p <= 0 {
        carrier.set(B3_SAMPLED_KEY, "0".to_string());
    } else if p == 1 {
        carrier.set(B3_SAMPLED_KEY, "1".to_string());
    } else {
        carrier.set(B3_FLAGS_KEY, "1".to_string());
    }
}

/// Returns the header keys used by B3 multi-header propagation.
pub fn keys() -> &'static [String] {
    B3_HEADER_KEYS.as_slice()
}

fn parse_trace_id(hex: &str) -> Option<u128> {
    // B3 spec mandates 16 or 32 hex chars; reject anything longer up front
    // so leading-zero-padded oversized inputs (which `u128::from_str_radix`
    // would otherwise accept) are treated as malformed.
    if hex.len() > 32 {
        dd_warn!("Propagator (b3multi): trace_id {hex:?} exceeds 32 hex chars");
        return None;
    }
    let id = match u128::from_str_radix(hex, 16) {
        Ok(id) => id,
        Err(e) => {
            dd_warn!("Propagator (b3multi): malformed trace_id {hex:?}: {e}");
            return None;
        }
    };
    if id == 0 {
        return None;
    }
    Some(id)
}

/// Parses a B3 span id. Returns `None` only on a hex-parse failure; an
/// explicit `0` value is accepted and returned as `Some(0)` so the caller
/// can distinguish "malformed" (reject the context) from "zero / no parent"
/// (accept the context with span_id 0).
fn parse_span_id(hex: &str) -> Option<u64> {
    if hex.len() > 16 {
        dd_warn!("Propagator (b3multi): span_id {hex:?} exceeds 16 hex chars");
        return None;
    }
    match u64::from_str_radix(hex, 16) {
        Ok(id) => Some(id),
        Err(e) => {
            dd_warn!("Propagator (b3multi): malformed span_id {hex:?}: {e}");
            None
        }
    }
}

fn extract_priority(carrier: &dyn Extractor) -> Option<SamplingPriority> {
    // `X-B3-Flags: 1` (debug) always takes precedence per the Python tracer.
    if carrier.get(B3_FLAGS_KEY) == Some("1") {
        return Some(priority::USER_KEEP);
    }
    match carrier.get(B3_SAMPLED_KEY) {
        Some("0") => Some(priority::AUTO_REJECT),
        Some("1") => Some(priority::AUTO_KEEP),
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

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn extract_missing_trace_id_returns_none() {
        let carrier = headers(&[("x-b3-sampled", "1")]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_64_bit_trace_id() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", "00f067aa0ba902b7"),
            ("x-b3-sampled", "1"),
        ]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8);
        assert_eq!(ctx.span_id, 0x00f0_67aa_0ba9_02b7);
        assert_eq!(ctx.sampling.priority, Some(priority::AUTO_KEEP));
        assert!(ctx.is_remote);
    }

    #[test]
    fn extract_128_bit_trace_id() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba864fe8b2a57d3eff7"),
            ("x-b3-spanid", "e457b5a2e4d86bd1"),
            ("x-b3-sampled", "0"),
        ]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8_64fe_8b2a_57d3_eff7u128);
        assert_eq!(ctx.span_id, 0xe457_b5a2_e4d8_6bd1);
        assert_eq!(ctx.sampling.priority, Some(priority::AUTO_REJECT));
    }

    #[test]
    fn extract_zero_trace_id_returns_none() {
        let carrier = headers(&[("x-b3-traceid", "0000000000000000"), ("x-b3-spanid", "1")]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_malformed_trace_id_returns_none() {
        let carrier = headers(&[("x-b3-traceid", "nothex"), ("x-b3-spanid", "1")]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_oversized_trace_id_returns_none() {
        let oversized = format!("{:033x}", 1u128);
        let carrier = headers(&[("x-b3-traceid", oversized.as_str()), ("x-b3-spanid", "1")]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_oversized_span_id_returns_none() {
        let oversized = format!("{:017x}", 1u64);
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", oversized.as_str()),
        ]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_missing_span_id_yields_zero() {
        let carrier = headers(&[("x-b3-traceid", "80f198ee56343ba8")]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.span_id, 0);
    }

    #[test]
    fn extract_zero_span_id_yields_zero() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", "0000000000000000"),
        ]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.span_id, 0);
    }

    #[test]
    fn extract_malformed_span_id_rejects_context() {
        // A valid trace id paired with a garbage span id must reject the
        // whole context — silently dropping a malformed span id to 0 could
        // let a bogus b3 context override later, valid propagation headers.
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", "nothex"),
        ]);
        assert_eq!(extract(&carrier), None);
    }

    #[test]
    fn extract_flags_debug_promotes_to_user_keep() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", "1"),
            ("x-b3-sampled", "0"),
            ("x-b3-flags", "1"),
        ]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.sampling.priority, Some(priority::USER_KEEP));
    }

    #[test]
    fn extract_unknown_sampled_value_defers_priority() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-sampled", "maybe"),
        ]);
        let ctx = extract(&carrier).unwrap();
        assert_eq!(ctx.sampling.priority, None);
    }

    #[test]
    fn inject_64_bit_trace_id_emits_16_hex() {
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
        assert_eq!(carrier["x-b3-traceid"], "80f198ee56343ba8");
        assert_eq!(carrier["x-b3-spanid"], "00f067aa0ba902b7");
        assert_eq!(carrier["x-b3-sampled"], "1");
        assert!(!carrier.contains_key("x-b3-flags"));
    }

    #[test]
    fn inject_128_bit_trace_id_emits_32_hex() {
        let mut ctx = SpanContext {
            trace_id: 0x80f1_98ee_5634_3ba8_64fe_8b2a_57d3_eff7u128,
            span_id: 0xe457_b5a2_e4d8_6bd1,
            sampling: Sampling {
                priority: Some(priority::AUTO_REJECT),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier["x-b3-traceid"], "80f198ee56343ba864fe8b2a57d3eff7");
        assert_eq!(carrier["x-b3-spanid"], "e457b5a2e4d86bd1");
        assert_eq!(carrier["x-b3-sampled"], "0");
    }

    #[test]
    fn inject_user_keep_emits_flags_not_sampled() {
        let mut ctx = SpanContext {
            trace_id: 1,
            span_id: 2,
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert_eq!(carrier.get("x-b3-flags").map(String::as_str), Some("1"));
        assert!(!carrier.contains_key("x-b3-sampled"));
    }

    #[test]
    fn inject_without_priority_omits_sampled_and_flags() {
        let mut ctx = SpanContext {
            trace_id: 1,
            span_id: 2,
            sampling: Sampling {
                priority: None,
                mechanism: None,
            },
            ..Default::default()
        };
        let mut carrier = HashMap::new();
        inject(&span_context_to_inject(&mut ctx), &mut carrier);
        assert!(!carrier.contains_key("x-b3-sampled"));
        assert!(!carrier.contains_key("x-b3-flags"));
    }

    #[test]
    fn propagator_dispatch_routes_to_b3multi() {
        let carrier = headers(&[
            ("x-b3-traceid", "80f198ee56343ba8"),
            ("x-b3-spanid", "1"),
            ("x-b3-sampled", "1"),
        ]);
        let propagator = TracePropagationStyle::B3Multi;
        let ctx = propagator
            .extract(&carrier, &Config::builder().build())
            .expect("b3multi dispatch should produce context");
        assert_eq!(ctx.trace_id, 0x80f1_98ee_5634_3ba8);
    }

    #[test]
    fn propagator_dispatch_exposes_keys() {
        let propagator = TracePropagationStyle::B3Multi;
        let k: &[String] = <TracePropagationStyle as Propagator<Config>>::keys(&propagator);
        assert_eq!(k.len(), 4);
        assert!(k.iter().any(|s| s == "x-b3-traceid"));
        assert!(k.iter().any(|s| s == "x-b3-spanid"));
        assert!(k.iter().any(|s| s == "x-b3-sampled"));
        assert!(k.iter().any(|s| s == "x-b3-flags"));
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

use crate::{
    carrier::Extractor,
    context::{Sampling, SpanContext},
    datadog::{DATADOG_LAST_PARENT_ID_KEY, DATADOG_SAMPLING_DECISION_KEY, INVALID_SEGMENT_REGEX},
    error::Error,
};

use dd_trace::{dd_debug, dd_error, dd_warn};

// Traceparent Keys
const TRACEPARENT_KEY: &str = "traceparent";
pub const TRACESTATE_KEY: &str = "tracestate";

lazy_static! {
    static ref TRACEPARENT_REGEX: Regex =
        Regex::new(r"(?i)^([a-f0-9]{2})-([a-f0-9]{32})-([a-f0-9]{16})-([a-f0-9]{2})(-.*)?$")
            .expect("failed creating regex");
    static ref INVALID_ASCII_CHARACTERS_REGEX: Regex =
        Regex::new(r"[^\x20-\x7E]+").expect("failed creating regex");
}

struct Traceparent {
    sampling_priority: i8,
    trace_id: u128,
    span_id: u64,
}

struct Tracestate {
    sampling_priority: Option<i8>,
    origin: Option<String>,
    lower_order_trace_id: Option<String>,
}

pub fn extract(carrier: &dyn Extractor) -> Option<SpanContext> {
    let tp = carrier.get(TRACEPARENT_KEY)?.trim();

    match extract_traceparent(tp) {
        Ok(traceparent) => {
            let mut tags = HashMap::new();
            tags.insert(TRACEPARENT_KEY.to_string(), tp.to_string());

            let mut origin = None;
            let mut sampling_priority = traceparent.sampling_priority;
            if let Some(ts) = carrier.get(TRACESTATE_KEY) {
                if let Some(tracestate) = extract_tracestate(ts, &mut tags) {
                    if let Some(lpid) = tracestate.lower_order_trace_id {
                        tags.insert(DATADOG_LAST_PARENT_ID_KEY.to_string(), lpid);
                    }

                    origin = tracestate.origin;

                    sampling_priority = define_sampling_priority(
                        traceparent.sampling_priority,
                        tracestate.sampling_priority,
                        &mut tags,
                    );
                }
            } else {
                dd_debug!("No `dd` value found in tracestate");
            }

            Some(SpanContext {
                trace_id: traceparent.trace_id,
                span_id: traceparent.span_id,
                sampling: Some(Sampling {
                    priority: Some(sampling_priority),
                    mechanism: None,
                }),
                origin,
                tags,
                links: Vec::new(),
            })
        }
        Err(e) => {
            dd_error!("Failed to extract traceparent: {e}");
            None
        }
    }
}

fn extract_tracestate(tracestate: &str, tags: &mut HashMap<String, String>) -> Option<Tracestate> {
    let ts_v = tracestate.split(',').map(str::trim);
    let ts = ts_v.clone().collect::<Vec<&str>>().join(",");

    if INVALID_ASCII_CHARACTERS_REGEX.is_match(&ts) {
        dd_debug!("Received invalid tracestate header {tracestate}");
        return None;
    }

    tags.insert(TRACESTATE_KEY.to_string(), ts.to_string());

    let mut dd: Option<HashMap<String, String>> = None;
    for v in ts_v.clone() {
        if let Some(stripped) = v.strip_prefix("dd=") {
            dd = Some(
                stripped
                    .split(';')
                    .filter_map(|item| {
                        let mut parts = item.splitn(2, ':');
                        Some((parts.next()?.to_string(), parts.next()?.to_string()))
                    })
                    .collect(),
            );
        }
    }

    if let Some(dd) = dd {
        let mut tracestate = Tracestate {
            sampling_priority: None,
            origin: None,
            lower_order_trace_id: None,
        };

        if let Some(ts_sp) = dd.get("s") {
            if let Ok(p_sp) = ts_sp.parse::<i8>() {
                tracestate.sampling_priority = Some(p_sp);
            }
        }

        if let Some(o) = dd.get("o") {
            tracestate.origin = Some(decode_tag_value(o));
        }

        if let Some(lo_tid) = dd.get("p") {
            tracestate.lower_order_trace_id = Some(lo_tid.to_string());
        }

        // Convert from `t.` to `_dd.p.`
        for (k, v) in &dd {
            if let Some(stripped) = k.strip_prefix("t.") {
                let nk = format!("_dd.p.{stripped}");
                tags.insert(nk, decode_tag_value(v));
            }
        }

        return Some(tracestate);
    }

    None
}

fn decode_tag_value(value: &str) -> String {
    value.replace('~', "=")
}

fn define_sampling_priority(
    traceparent_sampling_priority: i8,
    tracestate_sampling_priority: Option<i8>,
    tags: &mut HashMap<String, String>,
) -> i8 {
    if let Some(ts_sp) = tracestate_sampling_priority {
        if (traceparent_sampling_priority == 1 && ts_sp > 0)
            || (traceparent_sampling_priority == 0 && ts_sp < 0)
        {
            return ts_sp;
        }
    }

    if traceparent_sampling_priority == 1 {
        tags.insert(DATADOG_SAMPLING_DECISION_KEY.to_string(), "-0".to_string());
    } else if traceparent_sampling_priority == 0 {
        tags.remove(DATADOG_SAMPLING_DECISION_KEY);
    }

    traceparent_sampling_priority
}

fn extract_traceparent(traceparent: &str) -> Result<Traceparent, Error> {
    let captures = TRACEPARENT_REGEX
        .captures(traceparent)
        .ok_or_else(|| Error::extract("invalid traceparent", "traceparent"))?;

    let version = &captures[1];
    let trace_id = &captures[2];
    let span_id = &captures[3];
    let flags = &captures[4];
    let tail = captures.get(5).map_or("", |m| m.as_str());

    extract_version(version, tail)?;

    let trace_id = extract_trace_id(trace_id)?;
    let span_id = extract_span_id(span_id)?;

    let trace_flags = extract_trace_flags(flags)?;
    let sampling_priority = i8::from(trace_flags & 0x1 != 0);

    Ok(Traceparent {
        sampling_priority,
        trace_id,
        span_id,
    })
}

fn extract_version(version: &str, tail: &str) -> Result<(), Error> {
    match version {
        "ff" => {
            return Err(Error::extract(
                "`ff` is an invalid traceparent version",
                "traceparent",
            ))
        }
        "00" => {
            if !tail.is_empty() {
                return Err(Error::extract(
                    "Traceparent with version `00` should contain only 4 values delimited by `-`",
                    "traceparent",
                ));
            }
        }
        _ => {
            dd_warn!("Unsupported traceparent version {version}, still atempenting to parse");
        }
    }

    Ok(())
}

fn extract_trace_id(trace_id: &str) -> Result<u128, Error> {
    if INVALID_SEGMENT_REGEX.is_match(trace_id) {
        return Err(Error::extract(
            "`0` value for trace_id is invalid",
            "traceparent",
        ));
    }

    u128::from_str_radix(trace_id, 16)
        .map_err(|_| Error::extract("Failed to decode trace_id", "traceparent"))
}

fn extract_span_id(span_id: &str) -> Result<u64, Error> {
    if INVALID_SEGMENT_REGEX.is_match(span_id) {
        return Err(Error::extract(
            "`0` value for span_id is invalid",
            "traceparent",
        ));
    }

    u64::from_str_radix(span_id, 16)
        .map_err(|_| Error::extract("Failed to decode span_id", "traceparent"))
}

fn extract_trace_flags(flags: &str) -> Result<u8, Error> {
    if flags.len() != 2 {
        return Err(Error::extract("Invalid trace flags length", "traceparent"));
    }

    u8::from_str_radix(flags, 16)
        .map_err(|_| Error::extract("Failed to decode trace_flags", "traceparent"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::trace_propagation_style::TracePropagationStyle;

    use super::*;

    #[test]
    fn test_extract_traceparent_propagator() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:2;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(
            context.trace_id,
            171_395_628_812_617_415_352_188_477_958_425_669_623
        );
        assert_eq!(context.span_id, 67_667_974_448_284_343);
        assert_eq!(context.sampling.unwrap().priority, Some(2));
        assert_eq!(context.origin, Some("rum".to_string()));
        assert_eq!(
            context.tags.get("traceparent").unwrap(),
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01"
        );
        assert_eq!(
            context.tags.get("tracestate").unwrap(),
            "dd=p:00f067aa0ba902b7;s:2;o:rum"
        );
        assert_eq!(
            context.tags.get("_dd.parent_id").unwrap(),
            "00f067aa0ba902b7"
        );
    }

    #[test]
    fn test_extract_traceparent_dm_default() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags["_dd.p.dm"], "-0");
    }

    #[test]
    fn test_extract_traceparent_dm_default_with_tracestate_s_0() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:0;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags["_dd.p.dm"], "-0");
    }

    #[test]
    fn test_extract_traceparent_drop_dm_with_tracestate_s_not_present() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-00".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_traceparent_drop_dm_with_tracestate_s_1() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-00".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:1;o:rum".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .extract(&headers)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }
}

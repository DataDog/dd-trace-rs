// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, collections::HashMap, fmt::Write, str::FromStr, sync::LazyLock};

use crate::{
    core::{
        constants::SAMPLING_DECISION_MAKER_TAG_KEY,
        sampling::{mechanism, priority, SamplingMechanism, SamplingPriority},
    },
    dd_debug, dd_error, dd_warn,
    propagation::{
        carrier::{Extractor, Injector},
        context::{InjectSpanContext, Sampling, SpanContext, DATADOG_PROPAGATION_TAG_PREFIX},
        datadog::DATADOG_LAST_PARENT_ID_KEY,
        error::Error,
    },
};

// Traceparent Keys
/// W3C traceparent header key.
pub const TRACEPARENT_KEY: &str = "traceparent";
/// W3C tracestate header key.
pub const TRACESTATE_KEY: &str = "tracestate";

const TRACESTATE_MAX_MEMBERS: usize = 32;

const TRACESTATE_DD_KEY_MAX_LENGTH: usize = 256;
const TRACESTATE_OT_KEY_MAX_LENGTH: usize = 256;
const TRACESTATE_VALUES_SEPARATOR: &str = ",";
const TRACESTATE_DD_PAIR_SEPARATOR: &str = ";";
const TRACESTATE_SAMPLING_PRIORITY_KEY: &str = "s";
const TRACESTATE_ORIGIN_KEY: &str = "o";
const TRACESTATE_LAST_PARENT_KEY: &str = "p";
const TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX: &str = "t.";
const INVALID_CHAR_REPLACEMENT: char = '_';

static TRACECONTEXT_HEADER_KEYS: LazyLock<[String; 2]> =
    LazyLock::new(|| [TRACEPARENT_KEY.to_owned(), TRACESTATE_KEY.to_owned()]);

fn ot_parse_hex_56(s: &str, exact_len: Option<usize>) -> Option<u64> {
    if s.is_empty() || s.len() > 14 {
        return None;
    }
    if exact_len.filter(|n| s.len() != *n).is_some() {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

/// Extract `rv` from a raw `ot` member value, ignoring everything else.
pub(crate) fn ot_extract_rv(raw: &str) -> Option<u64> {
    raw.split(';').find_map(|item| match item.split_once(':') {
        Some(("rv", v)) => ot_parse_hex_56(v, Some(14)),
        _ => None,
    })
}

/// Removes malformed `rv`/`th` subkeys, preserving valid and unknown subkeys.
pub(crate) fn ot_sanitize(raw: &str) -> Option<String> {
    let parts: Vec<_> = raw
        .split(';')
        .filter(|item| match item.split_once(':') {
            Some(("rv", value)) => ot_parse_hex_56(value, Some(14)).is_some(),
            Some(("th", value)) => ot_parse_hex_56(value, None).is_some(),
            _ => true,
        })
        .collect();
    join_capped(&parts, TRACESTATE_OT_KEY_MAX_LENGTH)
}

/// Replaces `rv`/`th` in a raw `ot` member value, dropping the old ones and
/// appending everything else, in order, after the new pair. `None` when
/// nothing is left to emit.
pub(crate) fn ot_set_rv_th(raw: Option<&str>, rv: Option<u64>, th: Option<u64>) -> Option<String> {
    let format_th = |v: u64| {
        if v == 0 {
            "0".to_string()
        } else {
            format!("{v:014x}").trim_end_matches('0').to_string()
        }
    };
    let others = raw
        .into_iter()
        .flat_map(|s| s.split(';'))
        .filter(|item| !matches!(item.split_once(':'), Some(("rv", _)) | Some(("th", _))));

    let rv_part = rv.map(|v| format!("rv:{v:014x}"));
    let th_part = th.map(|v| format!("th:{}", format_th(v)));

    let parts: Vec<&str> = rv_part
        .as_deref()
        .into_iter()
        .chain(th_part.as_deref())
        .chain(others)
        .collect();
    join_capped(&parts, TRACESTATE_OT_KEY_MAX_LENGTH)
}

/// Joins leading `parts` with `;` capping length under `max_len`
fn join_capped(parts: &[&str], max_len: usize) -> Option<String> {
    let mut len = 0;
    let mut count = 0;
    for part in parts {
        let sep_len = if count == 0 { 0 } else { 1 };
        if len + sep_len + part.len() > max_len {
            break;
        }
        len += sep_len + part.len();
        count += 1;
    }
    (count > 0).then(|| parts[..count].join(";"))
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Traceparent {
    pub sampling_priority: SamplingPriority,
    pub trace_id: u128,
    pub span_id: u64,
}

/// Parsed W3C tracestate header containing Datadog-specific and vendor values.
///
/// The tracestate header allows vendors to propagate additional trace context
/// alongside the standard traceparent header.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Tracestate {
    pub(crate) sampling: Option<Sampling>,
    pub(crate) origin: Option<String>,
    pub(crate) lower_order_trace_id: Option<String>,
    pub(crate) propagation_tags: Option<HashMap<String, String>>,
    pub(crate) additional_values: Option<Vec<(String, String)>>,
    pub(crate) ot_member: Option<String>,
}

/// Code inspired, and copied, by OpenTelemetry Rust project.
/// <https://github.com/open-telemetry/opentelemetry-rust/blob/main/opentelemetry/src/trace/span_context.rs>
impl Tracestate {
    fn valid_key(key: &str) -> bool {
        if key.len() > 256 {
            return false;
        }

        let allowed_special = |b: u8| b == b'_' || b == b'-' || b == b'*' || b == b'/';
        let mut vendor_start = None;
        for (i, &b) in key.as_bytes().iter().enumerate() {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || allowed_special(b) || b == b'@') {
                return false;
            }

            if i == 0 && (!b.is_ascii_lowercase() && !b.is_ascii_digit()) {
                return false;
            } else if b == b'@' {
                if vendor_start.is_some() || i + 14 < key.len() {
                    return false;
                }
                vendor_start = Some(i);
            } else if let Some(start) = vendor_start {
                if i == start + 1 && !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
                    return false;
                }
            }
        }

        true
    }

    fn valid_value(value: &str) -> bool {
        if value.len() > 256 {
            return false;
        }

        !(value.contains(',') || value.contains('='))
    }
}

impl FromStr for Tracestate {
    type Err = String;
    fn from_str(tracestate: &str) -> Result<Self, Self::Err> {
        let ts_v = tracestate.split(',').take(TRACESTATE_MAX_MEMBERS);

        let mut dd: Option<HashMap<String, String>> = None;
        let mut additional_values = vec![];
        let mut ot: Option<String> = None;

        for v in ts_v {
            let (key, value) = v.split_once('=').unwrap_or(("", ""));

            if !Tracestate::valid_key(key) || value.is_empty() || !Tracestate::valid_value(value) {
                dd_debug!("Tracestate: invalid key or header value: {v}");
                return Err(String::from("Invalid tracestate"));
            }

            if key == "dd" {
                dd = Some(
                    value
                        .trim()
                        .split(';')
                        .filter_map(|item| {
                            if !item.as_bytes().iter().all(|c| matches!(c, b' '..=b'~')) {
                                None
                            } else {
                                let mut parts = item.splitn(2, ':');
                                Some((
                                    parts.next()?.to_string(),
                                    decode_tag_value(parts.next()?).to_string(),
                                ))
                            }
                        })
                        .collect(),
                );
            } else if key == "ot" {
                ot = Some(value.to_string());
            } else {
                additional_values.push((key.to_string(), value.to_string()));
            }
        }

        let mut tracestate = Tracestate {
            sampling: None,
            origin: None,
            lower_order_trace_id: None,
            propagation_tags: None,
            additional_values: None,
            ot_member: None,
        };

        // the original order must be maintained
        if !additional_values.is_empty() {
            tracestate.additional_values = Some(additional_values);
        }

        let propagation_tags = if let Some(dd) = dd {
            let mut tags = HashMap::new();
            let mut priority = None;
            let mut mechanism = None;

            for (k, v) in dd {
                match k.as_str() {
                    "s" => {
                        if let Ok(p_sp) = SamplingPriority::from_str(&v) {
                            priority = Some(p_sp);
                        }
                    }
                    "o" => tracestate.origin = Some(v),
                    "p" => tracestate.lower_order_trace_id = Some(v.to_string()),
                    "t.dm" => {
                        if let Ok(p_sm) = SamplingMechanism::from_str(&v) {
                            mechanism = Some(p_sm);
                        }
                        tags.insert(k, v);
                    }
                    _ => {
                        tags.insert(k, v);
                    }
                }
            }

            tracestate.sampling = Some(Sampling {
                priority,
                mechanism,
            });

            Some(tags)
        } else {
            dd_debug!("No `dd` value found in tracestate");
            None
        };

        tracestate.propagation_tags = propagation_tags;
        tracestate.ot_member = ot;

        Ok(tracestate)
    }
}

/// Tracestate data to be injected into outgoing requests.
///
/// Contains non-Datadog tracestate entries from the parent span that should
/// be propagated to downstream services.
pub struct InjectTraceState {
    header: String,
}

impl InjectTraceState {
    pub(crate) fn from_header(header: String) -> Self {
        Self { header }
    }

    pub(crate) fn additional_values(&self) -> impl Iterator<Item = &str> {
        self.header.split(',').filter(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            key != "dd"
                && !value.is_empty()
                && Tracestate::valid_key(key)
                && Tracestate::valid_value(value)
        })
    }
}

fn decode_tag_value(value: &str) -> Cow<'_, str> {
    if value.as_bytes().contains(&b'~') {
        Cow::Owned(value.replace('~', "="))
    } else {
        Cow::Borrowed(value)
    }
}

fn encode_tag_value(tag: &str) -> Cow<'_, str> {
    if tag.as_bytes().contains(&b'=') {
        Cow::Owned(tag.replace('=', "~"))
    } else {
        Cow::Borrowed(tag)
    }
}

/// Replace all characters in s that are either non ascii, or matched by f
fn replace_chars<MatchFn: Fn(u8) -> bool>(
    s: &str,
    f: MatchFn,
    replacement_char: char,
) -> Cow<'_, str> {
    // Fast first pass
    if s.as_bytes().iter().all(|c| c.is_ascii() && !f(*c)) {
        return Cow::Borrowed(s);
    }

    let mut replaced = String::new();
    let mut tail = s;
    loop {
        let Some((pos, _)) = tail
            .as_bytes()
            .iter()
            .enumerate()
            .find(|(_, c)| !c.is_ascii() || f(**c))
        else {
            replaced.push_str(tail);
            break;
        };

        replaced.push_str(&tail[..pos]);
        replaced.push(replacement_char);
        let offset = if !tail.as_bytes()[pos].is_ascii() {
            match tail[pos..].char_indices().nth(1) {
                Some((i, _)) => i,
                None => break,
            }
        } else {
            1
        };
        tail = &tail[pos + offset..];
    }
    Cow::Owned(replaced)
}

/// Inject trace context into a carrier using W3C Trace Context format.
pub fn inject(context: &InjectSpanContext, carrier: &mut dyn Injector) {
    if context.trace_id != 0 && context.span_id != 0 {
        inject_traceparent(context, carrier);
        inject_tracestate(context, carrier);
    } else {
        dd_debug!("Propagator (tracecontext): skipping inject");
    }
}

fn inject_traceparent(context: &InjectSpanContext, carrier: &mut dyn Injector) {
    // TODO: if higher trace_id 64bits are 0, we should verify _dd.p.tid is unset
    // if not 0, verify that `_dd.p.tid` is either unset or set to the encoded value of
    // the higher-order 64 bits

    let flags = context
        .sampling
        .priority
        .map(|priority| if priority.is_keep() { "01" } else { "00" })
        .unwrap_or("00");

    let traceparent = format!(
        "00-{:032x}-{:016x}-{flags}",
        context.trace_id, context.span_id
    );

    dd_debug!("Propagator (tracecontext): injecting traceparent: {traceparent}");

    carrier.set(TRACEPARENT_KEY, traceparent);
}

fn buf_appender(buf: &mut String) -> BufAppender<'_> {
    BufAppender {
        start: buf.len(),
        buf,
    }
}

struct BufAppender<'a> {
    start: usize,
    buf: &'a mut String,
}

impl BufAppender<'_> {
    fn push_str(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    fn appender(&mut self) -> BufAppender<'_> {
        BufAppender {
            start: self.buf.len(),
            buf: self.buf,
        }
    }

    fn truncate(&mut self, len: usize) {
        self.buf.truncate(self.start + len);
    }
}

fn append_dd_propagation_tags(context: &InjectSpanContext, tags_buffer: &mut BufAppender) {
    for (key, value) in context.tags.iter() {
        let Some(key_suffix) = key.strip_prefix(DATADOG_PROPAGATION_TAG_PREFIX) else {
            continue;
        };

        let t_key_suffix = replace_chars(
            key_suffix,
            |c| !matches!(c, b'!'..=b'+' | b'-'..=b'<' | b'>'..=b'~'),
            INVALID_CHAR_REPLACEMENT,
        );
        let encoded_value = replace_chars(
            value,
            |c| !matches!(c, b' '..=b'+' | b'-'..=b':' | b'<'..=b'}'),
            INVALID_CHAR_REPLACEMENT,
        );
        let encoded_value = encode_tag_value(&encoded_value);

        let entry_size = TRACESTATE_DD_PAIR_SEPARATOR.len()
            + TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX.len()
            + t_key_suffix.len()
            + 1
            + encoded_value.len();

        if tags_buffer.len() + entry_size > TRACESTATE_DD_KEY_MAX_LENGTH / 2 {
            break;
        }

        tags_buffer.push_str(super::const_concat!(
            TRACESTATE_DD_PAIR_SEPARATOR,
            TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX,
        ));
        tags_buffer.push_str(&t_key_suffix);
        tags_buffer.push_str(":");
        tags_buffer.push_str(&encoded_value);
    }
}

fn inject_tracestate(context: &InjectSpanContext, carrier: &mut dyn Injector) {
    let mut tracestate = String::with_capacity(256);
    let mut member_count = 1;

    tracestate.push_str("dd=");

    // Use a single String buffer to build the entire tracestate, avoiding intermediate allocations
    let mut dd_parts = buf_appender(&mut tracestate);

    // Build sampling priority part
    let priority = context.sampling.priority.unwrap_or(priority::USER_KEEP);
    dd_parts.push_str(super::const_concat!(TRACESTATE_SAMPLING_PRIORITY_KEY, ":",));
    dd_parts.push_str(&priority.to_string());

    // Build origin part if present
    if let Some(origin) = context.origin.as_ref() {
        let origin_encoded = replace_chars(
            origin,
            |c| !matches!(c, b' '..=b'+' | b'-'..=b':' | b'<'..=b'}'),
            INVALID_CHAR_REPLACEMENT,
        );
        let origin_encoded = replace_chars(origin_encoded.as_ref(), |c| c == b'=', '~');

        if dd_parts.len()
            + TRACESTATE_DD_PAIR_SEPARATOR.len()
            + TRACESTATE_ORIGIN_KEY.len()
            + 1
            + origin_encoded.len()
            < TRACESTATE_DD_KEY_MAX_LENGTH
        {
            dd_parts.push_str(super::const_concat!(
                TRACESTATE_DD_PAIR_SEPARATOR,
                TRACESTATE_ORIGIN_KEY,
                ":",
            ));
            dd_parts.push_str(&origin_encoded);
        }
    }

    // Build last parent id part
    let last_parent_id_part_start =
        dd_parts.len() + TRACESTATE_DD_PAIR_SEPARATOR.len() + TRACESTATE_LAST_PARENT_KEY.len() + 1;
    if last_parent_id_part_start + 16 < TRACESTATE_DD_KEY_MAX_LENGTH {
        // 16 chars for hex span_id

        dd_parts.push_str(super::const_concat!(
            TRACESTATE_DD_PAIR_SEPARATOR,
            TRACESTATE_LAST_PARENT_KEY,
            ":",
        ));

        if context.is_remote {
            if let Some(id) = context.tags.get(DATADOG_LAST_PARENT_ID_KEY) {
                dd_parts.push_str(id);
            } else {
                let _ = write!(&mut dd_parts.buf, "{:016x}", context.span_id);
            }
        } else {
            let _ = write!(&mut dd_parts.buf, "{:016x}", context.span_id);
        }
    }

    let index_before_tags = dd_parts.len();
    // Build propagation tags part
    let mut tags_buffer = dd_parts.appender();

    append_dd_propagation_tags(context, &mut tags_buffer);

    // Add tags part to dd_parts if there's room
    if tags_buffer.len() == 0 || dd_parts.len() >= TRACESTATE_DD_KEY_MAX_LENGTH {
        dd_parts.truncate(index_before_tags);
    }

    if let Some(ot) = context.ot_member {
        member_count += 1;
        let mut ot_part = buf_appender(&mut tracestate);
        ot_part.push_str(super::const_concat!(TRACESTATE_VALUES_SEPARATOR, "ot=",));
        ot_part.push_str(ot);
    }

    // Add additional tracestate values if present
    if let Some(ts) = &context.tracestate {
        for part in ts
            .additional_values()
            .take(TRACESTATE_MAX_MEMBERS - member_count)
        {
            tracestate.push_str(TRACESTATE_VALUES_SEPARATOR);
            tracestate.push_str(part)
        }
    }

    dd_debug!(
        "Propagator (tracecontext): injecting tracestate: {}",
        tracestate
    );

    carrier.set(TRACESTATE_KEY, tracestate);
}

/// Extract trace context from a carrier using W3C Trace Context format.
///
/// `DatadogCompositePropagator` calls `try_extract` instead; this is for direct
/// callers of the public propagation API (`_unstable_propagation`/`test-utils`).
#[allow(dead_code)]
pub fn extract(carrier: &dyn Extractor) -> Option<SpanContext> {
    match try_extract(carrier)? {
        Ok(context) => Some(context),
        Err(e) => {
            dd_error!("Propagator (tracecontext): Failed to extract traceparent: {e}");
            None
        }
    }
}

/// Same as [`extract`], but returns the error instead of logging it. The composite
/// propagator uses this so it can log once, after checking if another format recovered.
pub(crate) fn try_extract(carrier: &dyn Extractor) -> Option<Result<SpanContext, Error>> {
    let tp = carrier.get(TRACEPARENT_KEY)?.trim();

    match extract_traceparent(tp) {
        Ok(traceparent) => {
            dd_debug!("Propagator (tracecontext): traceparent extracted successfully");

            let mut tags = HashMap::new();
            tags.insert(TRACEPARENT_KEY.to_string(), tp.to_string());

            let mut origin = None;
            let mut sampling_priority = traceparent.sampling_priority;
            let mut mechanism = None;
            let tracestate: Option<Tracestate> = if let Some(raw_tracestate) =
                carrier.get(TRACESTATE_KEY)
            {
                if let Ok(tracestate) = Tracestate::from_str(raw_tracestate) {
                    dd_debug!("Propagator (tracecontext): tracestate header parsed successfully");

                    tags.insert(TRACESTATE_KEY.to_string(), raw_tracestate.to_string());

                    // Convert from `t.` to `_dd.p.`
                    if let Some(propagation_tags) = &tracestate.propagation_tags {
                        for (k, v) in propagation_tags {
                            if let Some(stripped) =
                                k.strip_prefix(TRACESTATE_DATADOG_PROPAGATION_TAG_PREFIX)
                            {
                                let nk = format!("{DATADOG_PROPAGATION_TAG_PREFIX}{stripped}");
                                tags.insert(nk, v.to_string());
                            }
                        }
                    }

                    if let Some(ref lpid) = tracestate.lower_order_trace_id {
                        tags.insert(DATADOG_LAST_PARENT_ID_KEY.to_string(), lpid.clone());
                    }

                    origin.clone_from(&tracestate.origin);

                    sampling_priority = define_sampling_priority(
                        traceparent.sampling_priority,
                        tracestate.sampling.unwrap_or_default().priority,
                        &mut tags,
                    );

                    mechanism = tags
                        .get(SAMPLING_DECISION_MAKER_TAG_KEY)
                        .and_then(|sm| SamplingMechanism::from_str(sm).ok());

                    Some(tracestate)
                } else {
                    dd_debug!("Propagator (tracecontext): unable to parse tracestate header");
                    None
                }
            } else {
                dd_debug!("Propagator (tracecontext): no tracestate header found");
                None
            };

            Some(Ok(SpanContext {
                trace_id: traceparent.trace_id,
                span_id: traceparent.span_id,
                sampling: Sampling {
                    priority: Some(sampling_priority),
                    mechanism,
                },
                origin,
                tags,
                links: Vec::new(),
                is_remote: true,
                tracestate,
            }))
        }
        Err(e) => Some(Err(e)),
    }
}

fn define_sampling_priority(
    traceparent_sampling_priority: SamplingPriority,
    tracestate_sampling_priority: Option<SamplingPriority>,
    tags: &mut HashMap<String, String>,
) -> SamplingPriority {
    if let Some(ts_sp) = tracestate_sampling_priority {
        // If the both traceparent and tracestate headers are sampled, keep the tracestate sampling
        // priority.
        if (traceparent_sampling_priority == priority::AUTO_KEEP && ts_sp.is_keep())
            || (traceparent_sampling_priority == priority::AUTO_REJECT && !ts_sp.is_keep())
        {
            return ts_sp;
        }
    }

    // If
    // * the tracestate sampling priority is missing
    // * the traceparent disagrees with the tracestate
    // Use the traceparent
    match traceparent_sampling_priority {
        priority::AUTO_KEEP => tags.insert(
            SAMPLING_DECISION_MAKER_TAG_KEY.to_string(),
            mechanism::DEFAULT.to_cow().into_owned(),
        ),
        priority::AUTO_REJECT => tags.remove(SAMPLING_DECISION_MAKER_TAG_KEY),
        _ => None,
    };

    traceparent_sampling_priority
}

fn take_char(s: &str, c: u8) -> Option<&str> {
    if s.is_empty() || s.as_bytes()[0] != c {
        return None;
    }
    Some(&s[1..])
}

fn take_n_hex_chars(s: &str, n: usize) -> Option<(&str, &str)> {
    if s.len() < n {
        return None;
    }
    for i in 0..n {
        if !matches!(s.as_bytes()[i], b'0'..=b'9' | b'a'..=b'f') {
            return None;
        }
    }
    Some(s.split_at(n))
}

fn parse_traceparent_components(traceparent: &str) -> Option<(&str, &str, &str, &str, &str)> {
    let (version, rest) = take_n_hex_chars(traceparent, 2)?;
    let rest = take_char(rest, b'-')?;
    let (trace_id, rest) = take_n_hex_chars(rest, 32)?;
    let rest = take_char(rest, b'-')?;
    let (span_id, rest) = take_n_hex_chars(rest, 16)?;
    let rest = take_char(rest, b'-')?;
    let (flags, rest) = take_n_hex_chars(rest, 2)?;
    let tail = if rest.is_empty() {
        ""
    } else {
        take_char(rest, b'-')?
    };
    Some((version, trace_id, span_id, flags, tail))
}

fn extract_traceparent(traceparent: &str) -> Result<Traceparent, Error> {
    let (version, trace_id, span_id, flags, tail) = parse_traceparent_components(traceparent)
        .ok_or(Error::extract("invalid traceparent", "traceparent"))?;

    let trace_id = extract_trace_id(trace_id)?;

    let span_id = extract_span_id(span_id)?;
    let trace_flags = extract_trace_flags(flags)?;

    extract_version(version, tail, trace_flags)?;

    let is_sampled = (trace_flags & 0x1) == 1;
    let sampling_priority = if is_sampled {
        priority::AUTO_KEEP
    } else {
        priority::AUTO_REJECT
    };

    Ok(Traceparent {
        sampling_priority,
        trace_id,
        span_id,
    })
}

fn extract_version(version: &str, tail: &str, trace_flags: u8) -> Result<(), Error> {
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
            if trace_flags > 2 {
                return Err(Error::extract(
                    "invalid trace flags for version 00",
                    "traceparent",
                ));
            }
        }
        _ => {
            dd_warn!("Propagator (tracecontext): Unsupported traceparent version {version}, still atempenting to parse");
        }
    }

    Ok(())
}

fn extract_trace_id(trace_id: &str) -> Result<u128, Error> {
    let trace_id = u128::from_str_radix(trace_id, 16)
        .map_err(|_| Error::extract("Failed to decode trace_id", "traceparent"))?;
    if trace_id == 0 {
        return Err(Error::extract(
            "`0` value for trace_id is invalid",
            "traceparent",
        ));
    }
    Ok(trace_id)
}

fn extract_span_id(span_id: &str) -> Result<u64, Error> {
    let span_id = u64::from_str_radix(span_id, 16)
        .map_err(|_| Error::extract("Failed to decode span_id", "traceparent"))?;
    if span_id == 0 {
        return Err(Error::extract(
            "`0` value for span_id is invalid",
            "traceparent",
        ));
    }
    Ok(span_id)
}

fn extract_trace_flags(flags: &str) -> Result<u8, Error> {
    if flags.len() != 2 {
        return Err(Error::extract("Invalid trace flags length", "traceparent"));
    }

    u8::from_str_radix(flags, 16)
        .map_err(|_| Error::extract("Failed to decode trace_flags", "traceparent"))
}

/// Returns the header keys used by W3C Trace Context propagation.
pub fn keys() -> &'static [String] {
    TRACECONTEXT_HEADER_KEYS.as_slice()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::core::{
        configuration::{Config, TracePropagationStyle},
        sampling::priority,
    };

    use crate::propagation::{
        context::{span_context_to_inject, InjectTraceState},
        Propagator,
    };

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
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
            .expect("couldn't extract trace context");

        assert_eq!(
            context.trace_id,
            171_395_628_812_617_415_352_188_477_958_425_669_623
        );
        assert_eq!(context.span_id, 67_667_974_448_284_343);
        assert_eq!(context.sampling.priority, Some(priority::USER_KEEP));
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
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
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
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
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
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
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
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
            .expect("couldn't extract trace context");

        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_traceparent_incorrect_trace_flags() {
        let headers = HashMap::from([(
            "traceparent".to_string(),
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-1x".to_string(),
        )]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator.try_extract(&headers, &Config::builder().build());

        assert!(matches!(context, Some(Err(_))));
    }

    #[test]
    fn test_extract_tracestate_incorrect_priority() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "01-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-02".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd=p:00f067aa0ba902b7;s:incorrect".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let context = propagator
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
            .expect("couldn't extract trace context");

        assert!(context.sampling.priority.is_some());
        assert_eq!(context.sampling.priority.unwrap(), priority::AUTO_REJECT);
    }

    #[test]
    fn test_extract_tracestate_ows_handling() {
        let headers = HashMap::from([
            (
                "traceparent".to_string(),
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01".to_string(),
            ),
            (
                "tracestate".to_string(),
                "dd= \t p:00f067aa0ba902b7;s:1,foo=1,bar= \t 2".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::TraceContext;

        let tracestate = propagator
            .try_extract(&headers, &Config::builder().build())
            .map(Result::unwrap)
            .expect("couldn't extract trace context")
            .tracestate
            .expect("tracestate should be extracted");

        assert_eq!(
            tracestate.sampling.unwrap().priority.unwrap(),
            priority::AUTO_KEEP
        );

        assert!(tracestate.additional_values.is_some());
        assert_eq!(
            tracestate.additional_values.unwrap(),
            vec![
                ("foo".to_string(), "1".to_string()),
                ("bar".to_string(), " \t 2".to_string()),
            ]
        );
    }

    #[test]
    fn test_inject_traceparent() {
        let mut context = InjectSpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some("foo,bar="),
            tags: &mut HashMap::from([(
                "_dd.p.foo bar,baz=".to_string(),
                "abc~!@#$%^&*()_+`-=".to_string(),
            )]),
            is_remote: false,
            tracestate: Some(InjectTraceState::from_header(
                "other=bleh,atel=test,dd=s:2;o:foo_bar_;t.dm:-4".to_owned(),
            )),
            ot_member: None,
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut context,
            &mut carrier,
            &Config::builder().build(),
        );

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert_eq!(
            carrier[TRACESTATE_KEY],
            "dd=s:2;o:foo_bar~;p:5555eeee6666ffff;t.foo_bar_baz_:abc_!@#$%^&*()_+`-~,other=bleh,atel=test"
        );
    }

    /// Builds a minimal local-root `InjectSpanContext` carrying `ot`, injects
    /// it, and returns the emitted `tracestate` string. Used by the OTel
    /// consistent-probability emission tests (APMAPI-2181, system-tests #7372).
    fn inject_with_ot(trace_id: u128, ot: Option<&str>) -> String {
        let mut tags = HashMap::new();
        let mut context = InjectSpanContext {
            trace_id,
            span_id: 0x5555_eeee_6666_ffff,
            sampling: Sampling {
                priority: Some(priority::AUTO_KEEP),
                mechanism: Some(mechanism::DEFAULT),
            },
            origin: None,
            tags: &mut tags,
            is_remote: false,
            tracestate: None,
            ot_member: ot,
        };
        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut context,
            &mut carrier,
            &Config::builder().build(),
        );
        carrier.get(TRACESTATE_KEY).cloned().unwrap_or_default()
    }

    // A1: probability decision emits rv;th matching the golden table (rate 0.1,
    // th = e6666666666666).
    #[test]
    fn emits_ot_on_probability_decision_rate_0_1() {
        let table = [
            (1u128, "f0948a54d43b8e"),
            (10, "65cd67504a538e"),
            (100, "fa060922e7438e"),
            (18444899399302180863, "ef284ace7a91e1"),
        ];
        for (tid, rv) in table {
            let injected = inject_with_ot(tid, Some(&format!("rv:{rv};th:e6666666666666")));
            assert!(
                injected.contains(&format!("ot=rv:{rv};th:e6666666666666")),
                "tid {tid}: got {injected}"
            );
        }
    }

    // A4: non-probability local decision erases th, forwards inherited rv.
    #[test]
    fn force_keep_clears_th_forwards_rv() {
        let injected = inject_with_ot(10, Some("rv:1234567890abcd"));
        assert!(injected.contains("ot=rv:1234567890abcd"), "got {injected}");
        assert!(!injected.contains("th:"), "got {injected}");
    }

    // A5: no ot to emit -> none fabricated.
    #[test]
    fn sampled_without_ot_not_fabricated() {
        let injected = inject_with_ot(10, None);
        assert!(!injected.contains("ot="), "got {injected}");
    }

    // ot is derived from trace id + rate, so it's emitted even on drop
    // (rate 0.1, trace_id 10 -> DROP: rv 65cd67504a538e < th e6666666666666).
    #[test]
    fn probability_drop_still_emits_ot() {
        let injected = inject_with_ot(10, Some("rv:65cd67504a538e;th:e6666666666666"));
        assert!(
            injected.contains("ot=rv:65cd67504a538e;th:e6666666666666"),
            "got {injected}"
        );
    }

    // #7372 ordering: `ot` sits right after `dd=`, before other vendors.
    #[test]
    fn ot_is_emitted_after_dd_before_other_vendors() {
        let mut tags = HashMap::new();
        let mut context = InjectSpanContext {
            trace_id: 0x1111aaaa2222bbbb3333cccc4444dddd,
            span_id: 0x5555_eeee_6666_ffff,
            sampling: Sampling {
                priority: Some(priority::AUTO_KEEP),
                mechanism: Some(mechanism::DEFAULT),
            },
            origin: None,
            tags: &mut tags,
            is_remote: false,
            tracestate: Some(InjectTraceState::from_header("congo=xyz".to_owned())),
            ot_member: Some("rv:ef284ace7a91e1;th:e6666666666666"),
        };
        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut context,
            &mut carrier,
            &Config::builder().build(),
        );
        let ts = &carrier[TRACESTATE_KEY];
        assert!(
            ts.contains("ot=rv:ef284ace7a91e1;th:e6666666666666,congo=xyz"),
            "got {ts}"
        );
        let dd = ts.find("dd=").unwrap();
        let ot = ts.find("ot=").unwrap();
        let congo = ts.find("congo=").unwrap();
        assert!(dd < ot && ot < congo, "expected dd<ot<congo, got {ts}");
    }

    #[test]
    fn test_inject_traceparent_with_256_max_length() {
        let origin = "abc".repeat(200);
        let mut context = InjectSpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some(&origin),
            tags: &mut HashMap::from([("_dd.p.foo".to_string(), "abc".to_string())]),
            is_remote: false,
            tracestate: None,
            ot_member: None,
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut context,
            &mut carrier,
            &Config::builder().build(),
        );

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert_eq!(
            carrier[TRACESTATE_KEY],
            "dd=s:2;p:5555eeee6666ffff;t.foo:abc"
        );
    }

    #[test]
    fn test_inject_traceparent_with_up_to_32_vendor_parts() {
        let mut tracestate = vec![];
        for index in 0..35 {
            tracestate.push(format!("state{index}=value-{index}"));
        }
        let tracestate = tracestate.join(",");

        let mut context = InjectSpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some("rum"),
            tags: &mut HashMap::from([("_dd.p.foo".to_string(), "abc".to_string())]),
            is_remote: false,
            tracestate: Some(InjectTraceState::from_header(tracestate)),
            ot_member: None,
        };

        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut context,
            &mut carrier,
            &Config::builder().build(),
        );

        assert_eq!(
            carrier[TRACEPARENT_KEY],
            "00-1111aaaa2222bbbb3333cccc4444dddd-5555eeee6666ffff-01"
        );

        assert!(carrier[TRACESTATE_KEY]
            .starts_with("dd=s:2;o:rum;p:5555eeee6666ffff;t.foo:abc,state0=value-0"));

        assert!(carrier[TRACESTATE_KEY].ends_with("state30=value-30"));
    }

    #[test]
    fn test_tracestate_with_tags_longer_than_limit() {
        let long_origin = "abcd".repeat(32);
        let long_tag = "abcd".repeat(30);
        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some(long_origin.clone()),
            tags: HashMap::from([("_dd.p.foo".to_string(), long_tag.clone())]),
            links: vec![],
            is_remote: false,
            tracestate: None,
        };
        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut span_context_to_inject(&mut context),
            &mut carrier,
            &Config::builder().build(),
        );
        assert_eq!(
            carrier[TRACESTATE_KEY],
            format!("dd=s:2;o:{long_origin};p:5555eeee6666ffff")
        );
    }

    #[test]
    fn test_tracestate_with_tags_shorter_than_limit() {
        #[allow(clippy::repeat_once)]
        let short_origin = "abcd".repeat(1);
        let long_tag = "abcd".repeat(30);
        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some(short_origin.clone()),
            tags: HashMap::from([("_dd.p.foo".to_string(), long_tag.clone())]),
            links: vec![],
            is_remote: false,
            tracestate: None,
        };
        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut span_context_to_inject(&mut context),
            &mut carrier,
            &Config::builder().build(),
        );
        assert_eq!(
            carrier[TRACESTATE_KEY],
            format!("dd=s:2;o:{short_origin};p:5555eeee6666ffff;t.foo:{long_tag}")
        );
    }

    #[test]
    fn test_tracestate_with_long_dd_tags() {
        #[allow(clippy::repeat_once)]
        let short_origin = "abcd".repeat(1);
        let long_tag = "abcd".repeat(32);
        let mut context = SpanContext {
            trace_id: u128::from_str_radix("1111aaaa2222bbbb3333cccc4444dddd", 16).unwrap(),
            span_id: u64::from_str_radix("5555eeee6666ffff", 16).unwrap(),
            sampling: Sampling {
                priority: Some(priority::USER_KEEP),
                mechanism: Some(mechanism::MANUAL),
            },
            origin: Some(short_origin.clone()),
            tags: HashMap::from([("_dd.p.foo".to_string(), long_tag.clone())]),
            links: vec![],
            is_remote: false,
            tracestate: None,
        };
        let mut carrier: HashMap<String, String> = HashMap::new();
        TracePropagationStyle::TraceContext.inject(
            &mut span_context_to_inject(&mut context),
            &mut carrier,
            &Config::builder().build(),
        );
        assert_eq!(
            carrier[TRACESTATE_KEY],
            format!("dd=s:2;o:{short_origin};p:5555eeee6666ffff")
        );
    }

    #[test]
    fn parses_ot_member_and_removes_it_from_additional_values() {
        let ts: Tracestate = "dd=s:2;t.dm:-3,ot=rv:ef284ace7a91e1;th:e6666666666666,congo=xyz"
            .parse()
            .unwrap();
        assert_eq!(
            ts.ot_member.as_deref(),
            Some("rv:ef284ace7a91e1;th:e6666666666666")
        );
        // ot removed from remainder; congo preserved
        let additional = ts.additional_values.unwrap();
        assert!(additional.iter().all(|(k, _)| k != "ot"));
        assert!(additional.iter().any(|(k, v)| k == "congo" && v == "xyz"));
    }

    #[test]
    fn ot_is_kept_raw_at_extraction_even_if_malformed() {
        let ts: Tracestate = "dd=s:1,ot=rv:not-hex-garbage;th:not-hex-either,congo=xyz123"
            .parse()
            .unwrap();
        // no parsing/validation happens at extraction; forwarded verbatim
        assert_eq!(
            ts.ot_member.as_deref(),
            Some("rv:not-hex-garbage;th:not-hex-either")
        );
        let additional = ts.additional_values.unwrap();
        assert!(additional
            .iter()
            .any(|(k, v)| k == "congo" && v == "xyz123"));
    }

    #[test]
    fn test_replace_chars() {
        let tests = vec![
            ("ac", "ac"),
            ("b", "_"),
            ("abbc", "a__c"),
            ("漢字", "__"),
            ("漢字c", "__c"),
            ("a漢b字c", "a___c"),
            ("漢a字c", "_a_c"),
            ("漢a字cb", "_a_c_"),
        ];
        for (input, expected) in tests {
            assert_eq!(replace_chars(input, |c| c == b'b', '_'), expected);
        }
    }

    #[test]
    fn ot_sanitize_drops_malformed_known_subkeys() {
        assert_eq!(
            ot_sanitize("rv:not-hex;th:invalid;future:value"),
            Some("future:value".to_string())
        );
        assert_eq!(
            ot_sanitize("rv:1234567890abcd;th:e6666666666666;future:value"),
            Some("rv:1234567890abcd;th:e6666666666666;future:value".to_string())
        );
    }

    #[test]
    fn ot_set_rv_th_formats_rv_padded_and_th_trimmed() {
        assert_eq!(
            ot_set_rv_th(None, Some(0x0028d980cf4f1c), None).as_deref(),
            Some("rv:0028d980cf4f1c")
        );
        assert_eq!(
            ot_set_rv_th(None, None, Some(0x80000000000000)).as_deref(),
            Some("th:8")
        );
        assert_eq!(ot_set_rv_th(None, None, Some(0)).as_deref(), Some("th:0"));
        assert_eq!(ot_set_rv_th(None, None, None), None);
    }

    #[test]
    fn ot_set_rv_th_replaces_old_pair_and_keeps_others() {
        assert_eq!(
            ot_set_rv_th(
                Some("rv:1234567890abcd;th:e6666666666666"),
                Some(0xf0948a54d43b8e),
                None
            )
            .as_deref(),
            Some("rv:f0948a54d43b8e")
        );

        // unrecognized sub-keys are kept, in order, after the new pair
        assert_eq!(
            ot_set_rv_th(
                Some("rv:1234567890abcd;fut:abc;th:e6666666666666"),
                Some(0xf0948a54d43b8e),
                Some(0xe6666666666666)
            )
            .as_deref(),
            Some("rv:f0948a54d43b8e;th:e6666666666666;fut:abc")
        );
    }

    #[test]
    fn ot_set_rv_th_caps_length_dropping_trailing_subkeys() {
        let huge = "z".repeat(300);
        let raw = format!("fut:{huge}");
        let result =
            ot_set_rv_th(Some(&raw), Some(0x1234567890abcd), Some(0xe6666666666666)).unwrap();
        assert!(result.len() <= 256, "got len {}", result.len());
        assert_eq!(result, "rv:1234567890abcd;th:e6666666666666");

        let raw = (0..40)
            .map(|i| format!("k{i}:{}", "a".repeat(10)))
            .collect::<Vec<_>>()
            .join(";");
        let result =
            ot_set_rv_th(Some(&raw), Some(0x1234567890abcd), Some(0xe6666666666666)).unwrap();
        assert!(result.len() <= 256, "got len {}", result.len());
        assert!(!result.ends_with(';'));
        assert!(result.starts_with("rv:1234567890abcd;th:e6666666666666"));
        for part in result.split(';') {
            assert!(part.starts_with("rv:") || part.starts_with("th:") || raw.contains(part));
        }
    }

    #[test]
    fn ot_extract_rv_finds_rv_regardless_of_position() {
        assert_eq!(
            ot_extract_rv("th:e6666666666666;rv:f0948a54d43b8e"),
            Some(0xf0948a54d43b8e)
        );
        assert_eq!(ot_extract_rv("th:e6666666666666"), None);
        assert_eq!(ot_extract_rv("rv:not-hex-garbage"), None);
    }
}

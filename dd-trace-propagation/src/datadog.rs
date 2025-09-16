// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, str::FromStr};

use lazy_static::lazy_static;
use regex::Regex;

use crate::{
    carrier::{Extractor, Injector},
    context::{
        combine_trace_id, split_trace_id, Sampling, SpanContext, DATADOG_PROPAGATION_TAG_PREFIX,
    },
    error::Error,
};

use dd_trace::{
    constants::SAMPLING_DECISION_MAKER_TAG_KEY,
    dd_debug, dd_error, dd_warn,
    sampling::{SamplingMechanism, SamplingPriority},
    Config,
};

// Datadog Keys
const DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY: &str = "_dd.p.tid";
const DATADOG_TRACE_ID_KEY: &str = "x-datadog-trace-id";
const DATADOG_ORIGIN_KEY: &str = "x-datadog-origin";
const DATADOG_PARENT_ID_KEY: &str = "x-datadog-parent-id";
const DATADOG_SAMPLING_PRIORITY_KEY: &str = "x-datadog-sampling-priority";
const DATADOG_TAGS_KEY: &str = "x-datadog-tags";
const DATADOG_PROPAGATION_ERROR_KEY: &str = "_dd.propagation_error";
pub const DATADOG_LAST_PARENT_ID_KEY: &str = "_dd.parent_id";

lazy_static! {
    pub static ref INVALID_SEGMENT_REGEX: Regex =
        Regex::new(r"^0+$").expect("failed creating regex");
    static ref VALID_SAMPLING_DECISION_REGEX: Regex =
        Regex::new(r"^-([0-9])$").expect("failed creating regex");
    static ref TAG_KEY_REGEX: Regex = Regex::new(r"^_dd\.p\.[\x21-\x2b\x2d-\x7e]+$").expect("failed creating regex"); // ASCII minus spaces and commas
    static ref TAG_VALUE_REGEX: Regex = Regex::new(r"^[\x20-\x2b\x2d-\x7e]*$").expect("failed creating regex"); // ASCII minus commas

    static ref DATADOG_HEADER_KEYS: [String; 5] = [
        DATADOG_TRACE_ID_KEY.to_owned(),
        DATADOG_ORIGIN_KEY.to_owned(),
        DATADOG_PARENT_ID_KEY.to_owned(),
        DATADOG_SAMPLING_PRIORITY_KEY.to_owned(),
        DATADOG_TAGS_KEY.to_owned()
    ];
}

pub fn inject(context: &mut SpanContext, carrier: &mut dyn Injector, config: &Config) {
    let tags = &mut context.tags;

    inject_trace_id(context.trace_id, carrier, tags);

    dd_debug!(
        "Propagator (datadog): injecting {DATADOG_PARENT_ID_KEY}: {}",
        context.span_id
    );
    carrier.set(DATADOG_PARENT_ID_KEY, context.span_id.to_string());

    if let Some(origin) = &context.origin {
        carrier.set(DATADOG_ORIGIN_KEY, origin.to_string());
    }

    inject_sampling(context.sampling, carrier, tags);
    inject_tags(tags, carrier, config.datadog_tags_max_length());
}

fn inject_trace_id(trace_id: u128, carrier: &mut dyn Injector, tags: &mut HashMap<String, String>) {
    let (higher, lower) = split_trace_id(trace_id);

    dd_debug!("Propagator (datadog): injecting {DATADOG_TRACE_ID_KEY}: {lower}");

    carrier.set(DATADOG_TRACE_ID_KEY, lower.to_string());

    if let Some(higher) = higher {
        tags.insert(
            DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY.to_string(),
            format!("{higher:016x}"),
        );
    } else {
        tags.remove(DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY);
    }
}

fn inject_sampling(
    sampling: Sampling,
    carrier: &mut dyn Injector,
    tags: &mut HashMap<String, String>,
) {
    if let Some(priority) = sampling.priority {
        dd_debug!("Propagator (datadog): injecting {DATADOG_SAMPLING_PRIORITY_KEY}: {priority}");

        carrier.set(DATADOG_SAMPLING_PRIORITY_KEY, priority.to_string())
    }

    if let Some(mechanism) = sampling.mechanism {
        tags.insert(
            SAMPLING_DECISION_MAKER_TAG_KEY.to_string(),
            mechanism.to_cow().into_owned(),
        );
    }
}

fn inject_tags(tags: &mut HashMap<String, String>, carrier: &mut dyn Injector, max_length: usize) {
    if max_length == 0 {
        tags.insert(
            DATADOG_PROPAGATION_ERROR_KEY.to_string(),
            "disabled".to_string(),
        );
        return;
    }

    match get_propagation_tags(tags, max_length) {
        Ok(propagation_tags) => {
            if !propagation_tags.is_empty() {
                dd_debug!("Propagator (datadog): injecting {DATADOG_TAGS_KEY}: {propagation_tags}");
                carrier.set(DATADOG_TAGS_KEY, propagation_tags);
            }
        }
        Err(err) => {
            tags.insert(
                DATADOG_PROPAGATION_ERROR_KEY.to_string(),
                err.message.to_string(),
            );
            dd_error!("Propagator (datadog): Error getting propagation tags {err}");
        }
    }
}

fn get_propagation_tags(
    tags: &HashMap<String, String>,
    max_length: usize,
) -> Result<String, Error> {
    let propagation_tags = tags
        .iter()
        .filter(|(key, _)| key.starts_with(DATADOG_PROPAGATION_TAG_PREFIX))
        .map(|(key, value)| {
            if !validate_tag_key(key) || !validate_tag_value(value) {
                return Err(Error::inject("encoding_error", "datadog"));
            }

            Ok(format!("{key}={value}"))
        })
        .collect::<Result<Vec<String>, _>>()?
        .join(",");

    if propagation_tags.len() > max_length {
        Err(Error::inject("inject_max_size", "datadog"))
    } else {
        Ok(propagation_tags)
    }
}

fn validate_tag_key(key: &str) -> bool {
    TAG_KEY_REGEX.is_match(key)
}

fn validate_tag_value(value: &str) -> bool {
    TAG_VALUE_REGEX.is_match(value)
}

pub fn extract(carrier: &dyn Extractor, config: &Config) -> Option<SpanContext> {
    let lower_trace_id = match extract_trace_id(carrier) {
        Ok(trace_id) => trace_id?,
        Err(e) => {
            dd_error!("Propagator (datadog): Error extracting trace_id {e}");
            return None;
        }
    };

    let parent_id = match extract_parent_id(carrier) {
        Ok(parent_id) => parent_id.unwrap_or_default(),
        Err(e) => {
            dd_error!("Propagator (datadog): Error extracting parent_id {e}");
            0
        }
    };

    let origin = extract_origin(carrier);
    let tags = extract_tags(carrier, config.datadog_tags_max_length());

    let sampling = match extract_sampling_priority(carrier) {
        Ok(sampling_priority) => Sampling {
            priority: sampling_priority,
            mechanism: if sampling_priority.is_some() {
                tags.get(SAMPLING_DECISION_MAKER_TAG_KEY)
                    .map(|sm| SamplingMechanism::from_str(sm).ok())
                    .unwrap_or_default()
            } else {
                None
            },
        },
        Err(e) => {
            dd_warn!("Propagator (datadog): Error extracting sampling priority {e}");
            Sampling {
                priority: None,
                mechanism: None,
            }
        }
    };

    let trace_id = combine_trace_id(
        lower_trace_id,
        tags.get(DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY),
    );

    Some(SpanContext {
        trace_id,
        span_id: parent_id,
        sampling,
        origin,
        tags,
        links: Vec::new(),
        is_remote: true,
        tracestate: None,
    })
}

fn extract_trace_id(carrier: &dyn Extractor) -> Result<Option<u64>, Error> {
    let trace_id = match carrier.get(DATADOG_TRACE_ID_KEY) {
        Some(trace_id) => trace_id,
        None => return Ok(None),
    };

    if INVALID_SEGMENT_REGEX.is_match(trace_id) {
        return Err(Error::extract("Invalid `trace_id` found", "datadog"));
    }

    trace_id
        .parse::<u64>()
        .map(Some)
        .map_err(|_| Error::extract("Failed to decode `trace_id`", "datadog"))
}

fn extract_parent_id(carrier: &dyn Extractor) -> Result<Option<u64>, Error> {
    let parent_id = match carrier.get(DATADOG_PARENT_ID_KEY) {
        Some(parent_id) => parent_id,
        None => return Ok(None),
    };

    parent_id
        .parse::<u64>()
        .map(Some)
        .map_err(|_| Error::extract("Failed to decode `parent_id`", "datadog"))
}

fn extract_sampling_priority(carrier: &dyn Extractor) -> Result<Option<SamplingPriority>, Error> {
    carrier
        .get(DATADOG_SAMPLING_PRIORITY_KEY)
        .map(SamplingPriority::from_str)
        .transpose()
        .map_err(|_| Error::extract("Failed to decode `sampling_priority`", "datadog"))
}

fn extract_origin(carrier: &dyn Extractor) -> Option<String> {
    let origin = carrier.get(DATADOG_ORIGIN_KEY)?;
    Some(origin.to_string())
}

fn extract_tags(carrier: &dyn Extractor, max_length: usize) -> HashMap<String, String> {
    let mut tags: HashMap<String, String> = HashMap::new();

    let carrier_tags = carrier.get(DATADOG_TAGS_KEY).unwrap_or_default();

    if carrier_tags.len() > max_length {
        let error_message = if max_length == 0 {
            "disabled"
        } else {
            "extract_max_size"
        };

        tags.insert(
            DATADOG_PROPAGATION_ERROR_KEY.to_string(),
            error_message.to_string(),
        );

        return tags;
    }

    let pairs = carrier_tags.split(',');
    for pair in pairs {
        if let Some((k, v)) = pair.split_once('=') {
            // todo: reject key on tags extract reject
            if k.starts_with(DATADOG_PROPAGATION_TAG_PREFIX) {
                tags.insert(k.to_string(), v.to_string());
            }
        }
    }

    // Handle 128bit trace ID
    if let Some(trace_id_higher_order_bits) = tags.get(DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY) {
        if !higher_order_bits_valid(trace_id_higher_order_bits) {
            dd_warn!("Malformed Trace ID: {trace_id_higher_order_bits} Failed to decode trace ID from carrier.");
            tags.insert(
                DATADOG_PROPAGATION_ERROR_KEY.to_string(),
                format!("malformed_tid {trace_id_higher_order_bits}"),
            );
            tags.remove(DATADOG_HIGHER_ORDER_TRACE_ID_BITS_KEY);
        }
    }

    validate_sampling_decision(&mut tags);

    tags
}

fn validate_sampling_decision(tags: &mut HashMap<String, String>) {
    let should_remove =
        tags.get(SAMPLING_DECISION_MAKER_TAG_KEY)
            .is_some_and(|sampling_decision| {
                let is_invalid = !VALID_SAMPLING_DECISION_REGEX.is_match(sampling_decision);
                if is_invalid {
                    dd_warn!("Failed to decode `_dd.p.dm`: {}", sampling_decision);
                }
                is_invalid
            });

    if should_remove {
        tags.remove(SAMPLING_DECISION_MAKER_TAG_KEY);
        tags.insert(
            DATADOG_PROPAGATION_ERROR_KEY.to_string(),
            "decoding_error".to_string(),
        );
    }
}

fn higher_order_bits_valid(trace_id_higher_order_bits: &str) -> bool {
    if trace_id_higher_order_bits.len() != 16 {
        return false;
    }

    match u64::from_str_radix(trace_id_higher_order_bits, 16) {
        Ok(_) => {}
        Err(_) => return false,
    }

    true
}

pub fn keys() -> &'static [String] {
    DATADOG_HEADER_KEYS.as_slice()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use dd_trace::{
        configuration::TracePropagationStyle,
        sampling::{mechanism, priority},
    };

    use crate::{context::split_trace_id, Propagator};

    use super::*;

    #[test]
    fn test_extract_datadog_propagator() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.test=value,_dd.p.tid=0000000000004321,any=tag".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(&headers, &Config::builder().build())
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 317_007_296_906_698_644_522_194);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, Some(priority::AUTO_KEEP));
        assert_eq!(context.origin, Some("synthetics".to_string()));

        assert_eq!(context.tags.get("_dd.p.test").unwrap(), "value");
        assert_eq!(context.tags.get("_dd.p.tid").unwrap(), "0000000000004321");
        assert_eq!(context.tags.get("_dd.p.dm"), None);

        let (higher, lower) = split_trace_id(context.trace_id);
        assert_eq!(higher, u64::from_str_radix("0000000000004321", 16).ok());
        assert_eq!(lower, 1234);
    }

    #[test]
    fn test_extract_datadog_propagator_with_malformed_traceid() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.test=value,_dd.p.tid=4321,any=tag".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(&headers, &Config::builder().build())
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 1234);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, Some(priority::AUTO_KEEP));
        assert_eq!(context.origin, Some("synthetics".to_string()));
        println!("{:?}", context.tags);
        assert_eq!(context.tags.get("_dd.p.test").unwrap(), "value");
        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_datadog_propagator_64_simple() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.test=value,any=tag".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(&headers, &Config::builder().build())
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 1234);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, Some(priority::AUTO_KEEP));
        assert_eq!(context.origin, Some("synthetics".to_string()));
        println!("{:?}", context.tags);
        assert_eq!(context.tags.get("_dd.p.test").unwrap(), "value");
        assert_eq!(context.tags.get("_dd.p.tid"), None);
        assert_eq!(context.tags.get("_dd.p.dm"), None);
    }

    #[test]
    fn test_extract_datadog_propagator_very_long_tags() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            ("x-datadog-sampling-priority".to_string(), "1".to_string()),
            ("x-datadog-origin".to_string(), "synthetics".to_string()),
            (
                "x-datadog-tags".to_string(),
                "_dd.p.test=value,any=tag".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(
                &headers,
                &Config::builder().set_datadog_tags_max_length(5).build(),
            )
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 1234);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, Some(priority::AUTO_KEEP));
        assert_eq!(context.origin, Some("synthetics".to_string()));

        assert_eq!(
            context.tags.get("_dd.propagation_error").unwrap(),
            "extract_max_size"
        );
    }

    #[test]
    fn test_extract_datadog_propagator_incorrect_sampling_priority() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
            (
                "x-datadog-sampling-priority".to_string(),
                "incorrect".to_string(),
            ),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(&headers, &Config::builder().build())
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 1234);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, None);
        assert_eq!(context.sampling.mechanism, None);
    }

    #[test]
    fn test_extract_datadog_propagator_missing_sampling_priority() {
        let headers = HashMap::from([
            ("x-datadog-trace-id".to_string(), "1234".to_string()),
            ("x-datadog-parent-id".to_string(), "5678".to_string()),
        ]);

        let propagator = TracePropagationStyle::Datadog;

        let context = propagator
            .extract(&headers, &Config::builder().build())
            .expect("couldn't extract trace context");

        assert_eq!(context.trace_id, 1234);
        assert_eq!(context.span_id, 5678);
        assert_eq!(context.sampling.priority, None);
    }

    #[test]
    fn test_inject_datadog_propagator() {
        let mut tags = HashMap::new();
        tags.set("_dd.p.test", "value".to_string());
        tags.set("_dd.any", "tag".to_string());

        let mut context = SpanContext {
            trace_id: 1234,
            span_id: 5678,
            sampling: Sampling {
                priority: Some(priority::AUTO_KEEP),
                mechanism: None,
            },
            origin: Some("synthetics".to_string()),
            tags,
            links: vec![],
            is_remote: true,
            tracestate: None,
        };

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier[DATADOG_TRACE_ID_KEY], "1234");
        assert_eq!(carrier[DATADOG_PARENT_ID_KEY], "5678");
        assert_eq!(carrier[DATADOG_ORIGIN_KEY], "synthetics");
        assert_eq!(carrier[DATADOG_SAMPLING_PRIORITY_KEY], "1");
    }

    fn get_span_context(trace_id: Option<u128>) -> SpanContext {
        let mut tags = HashMap::new();
        tags.set("_dd.any", "tag".to_string());

        let trace_id = trace_id.unwrap_or(171_395_628_812_617_415_352_188_477_958_425_669_623);
        SpanContext {
            trace_id,
            span_id: 5678,
            sampling: Sampling {
                priority: Some(priority::AUTO_KEEP),
                mechanism: None,
            },
            origin: Some("synthetics".to_string()),
            tags,
            links: vec![],
            is_remote: true,
            tracestate: None,
        }
    }

    #[test]
    fn test_inject_datadog_propagator_128bit() {
        let trace_id: u128 = 171_395_628_812_617_415_352_188_477_958_425_669_623;
        let lower = trace_id as u64;
        let higher = (trace_id >> 64) as u64;

        let mut context = get_span_context(None);

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier[DATADOG_TRACE_ID_KEY], lower.to_string());
        assert_eq!(carrier[DATADOG_ORIGIN_KEY], "synthetics");
        assert_eq!(
            carrier[DATADOG_TAGS_KEY],
            format!("_dd.p.tid={higher:016x}")
        );
    }

    #[test]
    fn test_inject_datadog_decision_marker() {
        let mut context = get_span_context(Some(42));
        context.sampling = Sampling {
            priority: Some(priority::AUTO_KEEP),
            mechanism: Some(mechanism::MANUAL),
        };

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier[DATADOG_TAGS_KEY], "_dd.p.dm=-4");
    }

    #[test]
    fn test_inject_datadog_propagator_invalid_tag_key() {
        let mut context = get_span_context(None);

        context.tags.set("_dd.p.a,ny", "invalid".to_string());
        context.tags.set("_dd.p.valid", "valid".to_string());

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier.get(DATADOG_TAGS_KEY), None);
    }

    #[test]
    fn test_inject_datadog_drop_long_tags() {
        let mut context = get_span_context(None);

        context
            .tags
            .set("_dd.p.foo", "valid".repeat(500).to_string());

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier.get(DATADOG_TAGS_KEY), None);
    }

    #[test]
    fn test_inject_datadog_tags_disabled() {
        let mut context = get_span_context(None);

        context.tags.set("_dd.p.foo", "valid".to_string());

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(
            &mut context,
            &mut carrier,
            &Config::builder().set_datadog_tags_max_length(0).build(),
        );

        assert_eq!(carrier.get(DATADOG_TAGS_KEY), None);
    }

    #[test]
    fn test_inject_datadog_drop_invalid_value_tags() {
        let mut context = get_span_context(None);

        context.tags.set("_dd.p.foo", "hélicoptère".to_string());

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier.get(DATADOG_TAGS_KEY), None);
    }

    #[test]
    fn test_inject_datadog_remove_tid_propagation_tag() {
        let mut context = get_span_context(Some(42));

        context.tags.set("_dd.p.tid", "c0ffee".to_string());
        context.tags.set("_dd.p.other", "test".to_string());

        let propagator = TracePropagationStyle::Datadog;

        let mut carrier = HashMap::new();
        propagator.inject(&mut context, &mut carrier, &Config::builder().build());

        assert_eq!(carrier[DATADOG_TAGS_KEY], "_dd.p.other=test");
    }
}

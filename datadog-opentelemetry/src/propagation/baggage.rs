// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! W3C Baggage propagation (`baggage` header).
//!
//! This module exposes the header key so the composite propagator can include it in its `fields()`
//! list. It contains only extraction code.
//!
//! Injections is performed by [`opentelemetry_sdk::propagation::BaggagePropagator`]
//! at the [`DatadogPropagator`](crate::text_map_propagator::DatadogPropagator) layer, which has
//! access to the OTel [`Context`](opentelemetry::Context) that carries baggage.
use std::sync::LazyLock;

use opentelemetry::baggage::{Baggage, KeyValueMetadata};
use percent_encoding::percent_decode_str;

use crate::{dd_warn, propagation::carrier::Extractor};

/// The W3C `baggage` header name.
pub const BAGGAGE_KEY: &str = "baggage";

/// Extract only the first [`MAX_BAGGAGE_MEMBERS`] entries of the baggage header
/// members the max entry coming after are ignored
const MAX_BAGGAGE_MEMBERS: usize = 32;

/// Extract only the up to [`MAX_BAGGAGE_LENGTH`] entries of the baggage header
/// members that would make us look at more than the max bytes of the header are ignored
const MAX_BAGGAGE_LENGTH: usize = 1024;

static BAGGAGE_HEADER_KEYS: LazyLock<[String; 1]> = LazyLock::new(|| [BAGGAGE_KEY.to_owned()]);

/// Returns the header keys used by the W3C baggage propagator.
pub fn keys() -> &'static [String] {
    BAGGAGE_HEADER_KEYS.as_slice()
}

fn parse_baggage_member(baggage_member: &str) -> Option<KeyValueMetadata> {
    let mut member = baggage_member.split(';');
    let Some(name_and_value) = member.next() else {
        dd_warn!("Propagator (baggage): invalid format");
        return None;
    };
    let mut iter = name_and_value.split('=');
    let (Some(name), Some(value)) = (iter.next(), iter.next()) else {
        dd_warn!("Propagator (baggage): invalid key-value format");
        return None;
    };
    let decode_name = percent_decode_str(name).decode_utf8();
    let decode_value = percent_decode_str(value).decode_utf8();

    let (Ok(name), Ok(value)) = (decode_name, decode_value) else {
        dd_warn!("Propagator (baggage): invalid percent encoded UTF8 string in key values");
        return None;
    };

    let name = name.trim();
    let value = value.trim();
    if name.is_empty() || value.is_empty() {
        dd_warn!("Propagator (baggage): empty key or value");
        return None;
    }

    // decode and trim metadata entries associated with the key-value
    let decoded_props = member
        .flat_map(|prop| percent_decode_str(prop).decode_utf8())
        .enumerate()
        .fold(String::new(), |mut acc, (i, prop)| {
            if i != 0 {
                acc.push(';');
            }
            acc.push_str(prop.trim());
            acc
        });

    Some(KeyValueMetadata::new(
        name.to_owned(),
        value.to_string(),
        decoded_props,
    ))
}

pub(crate) fn extract_baggage(extractor: &dyn Extractor) -> Option<Baggage> {
    let header_value = extractor.get(BAGGAGE_KEY)?;
    let mut members = 0;
    let mut allocated_size = 0;
    let baggage = header_value.split(',')
        .take_while(|member| {
            allocated_size += member.len();
            let drop_entry = allocated_size > MAX_BAGGAGE_LENGTH;
            if drop_entry {
                dd_warn!("Propagator (baggage): ignored baggage key-values, only first {} bytes propagated", MAX_BAGGAGE_LENGTH)
            }
            !drop_entry
        })
        .map(parse_baggage_member)
        .take_while(Option::is_some)
        .flatten()
        .take_while(|_| {
            members +=1;
            let drop_entry = members > MAX_BAGGAGE_MEMBERS;
            if drop_entry {
                dd_warn!("Propagator (baggage): ignored baggage key-values, only first {} propagated", MAX_BAGGAGE_MEMBERS)
            }
            !drop_entry
        });
    Some(Baggage::from(baggage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::{baggage::BaggageMetadata, Key, StringValue};
    use std::collections::HashMap;

    fn valid_extract_data() -> Vec<(&'static str, HashMap<Key, StringValue>)> {
        vec![
            // "valid w3cHeader"
            (
                "key1=val1,key2=val2",
                vec![
                    (Key::new("key1"), StringValue::from("val1")),
                    (Key::new("key2"), StringValue::from("val2")),
                ]
                .into_iter()
                .collect(),
            ),
            // "valid w3cHeader with spaces"
            (
                "key1 =   val1,  key2 =val2   ",
                vec![
                    (Key::new("key1"), StringValue::from("val1")),
                    (Key::new("key2"), StringValue::from("val2")),
                ]
                .into_iter()
                .collect(),
            ),
            // "valid header with url-escaped comma"
            (
                "key1=val1,key2=val2%2Cval3",
                vec![
                    (Key::new("key1"), StringValue::from("val1")),
                    (Key::new("key2"), StringValue::from("val2,val3")),
                ]
                .into_iter()
                .collect(),
            ),
            // "valid header with an invalid header"
            (
                "key1=val1,key2=val2,a,val3",
                vec![
                    (Key::new("key1"), StringValue::from("val1")),
                    (Key::new("key2"), StringValue::from("val2")),
                ]
                .into_iter()
                .collect(),
            ),
        ]
    }

    #[allow(clippy::type_complexity)]
    fn valid_extract_data_with_metadata(
    ) -> Vec<(&'static str, HashMap<Key, (StringValue, BaggageMetadata)>)> {
        vec![
            // "valid w3cHeader with properties"
            ("key1=val1,key2=val2;prop=1", vec![(Key::new("key1"), (StringValue::from("val1"), BaggageMetadata::default())), (Key::new("key2"), (StringValue::from("val2"), BaggageMetadata::from("prop=1")))].into_iter().collect()),
            // prop can don't need to be key value pair
            ("key1=val1,key2=val2;prop1", vec![(Key::new("key1"), (StringValue::from("val1"), BaggageMetadata::default())), (Key::new("key2"), (StringValue::from("val2"), BaggageMetadata::from("prop1")))].into_iter().collect()),
            ("key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue",
             vec![
                 (Key::new("key1"), (StringValue::from("value1"), BaggageMetadata::from("property1;property2"))),
                 (Key::new("key2"), (StringValue::from("value2"), BaggageMetadata::default())),
                 (Key::new("key3"), (StringValue::from("value3"), BaggageMetadata::from("propertyKey=propertyValue"))),
             ].into_iter().collect()),
        ]
    }

    #[test]
    fn test_extract_baggage() {
        for (header_value, kvs) in valid_extract_data() {
            let mut extractor: HashMap<String, String> = HashMap::new();
            extractor.insert(BAGGAGE_KEY.to_string(), header_value.to_string());
            let baggage = extract_baggage(&extractor).expect("baggage extracted");

            assert_eq!(kvs.len(), baggage.len());
            for (key, (value, _metadata)) in &baggage {
                assert_eq!(Some(value), kvs.get(key))
            }
        }
    }

    #[test]
    fn test_extract_baggage_with_metadata() {
        for (header_value, kvm) in valid_extract_data_with_metadata() {
            let mut extractor: HashMap<String, String> = HashMap::new();
            extractor.insert(BAGGAGE_KEY.to_string(), header_value.to_string());
            let baggage = extract_baggage(&extractor).expect("baggage extracted");

            assert_eq!(kvm.len(), baggage.len());
            for (key, value_and_prop) in &baggage {
                assert_eq!(Some(value_and_prop), kvm.get(key))
            }
        }
    }

    #[test]
    fn test_extract_baggage_respects_max_members() {
        let total = MAX_BAGGAGE_MEMBERS + 8;
        let header_value = (0..total)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join(",");

        let mut extractor: HashMap<String, String> = HashMap::new();
        extractor.insert(BAGGAGE_KEY.to_string(), header_value);
        let baggage = extract_baggage(&extractor).expect("baggage extracted");

        assert_eq!(baggage.len(), MAX_BAGGAGE_MEMBERS);
        for i in 0..MAX_BAGGAGE_MEMBERS {
            let key = Key::new(format!("k{i}"));
            assert_eq!(
                baggage.get(&key).map(|v| v.as_str()),
                Some(format!("v{i}").as_str())
            );
        }
        for i in MAX_BAGGAGE_MEMBERS..total {
            let key = Key::new(format!("k{i}"));
            assert!(baggage.get(&key).is_none());
        }
    }

    #[test]
    fn test_extract_baggage_respects_max_length() {
        // Each member is exactly 50 bytes: "k{NN}={padding...}".
        // 21 members * 50 = 1050 bytes (separators excluded by the
        // implementation), so the 21st entry pushes allocated_size past
        // MAX_BAGGAGE_LENGTH (1024) and must be dropped.
        let member_size = 50;
        let total = 25;
        let members: Vec<String> = (0..total)
            .map(|i| {
                let prefix = format!("k{i:02}=");
                let pad = "x".repeat(member_size - prefix.len());
                format!("{prefix}{pad}")
            })
            .collect();
        assert!(members.iter().map(|m| m.len()).sum::<usize>() > MAX_BAGGAGE_MEMBERS);
        let header_value = members.join(",");

        let mut extractor: HashMap<String, String> = HashMap::new();
        extractor.insert(BAGGAGE_KEY.to_string(), header_value);
        let baggage = extract_baggage(&extractor).expect("baggage extracted");

        let expected_kept = MAX_BAGGAGE_LENGTH / member_size;
        assert_eq!(baggage.len(), expected_kept);
        for i in 0..expected_kept {
            let key = Key::new(format!("k{i:02}"));
            assert!(
                baggage.get(&key).is_some(),
                "expected key k{i:02} to be present"
            );
        }
        for i in expected_kept..total {
            let key = Key::new(format!("k{i:02}"));
            assert!(
                baggage.get(&key).is_none(),
                "expected key k{i:02} to be dropped"
            );
        }
    }
}

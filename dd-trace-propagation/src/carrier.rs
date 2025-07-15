// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

/// Code inspired, and copied, by OpenTelemetry Rust project.
/// <https://github.com/open-telemetry/opentelemetry-rust/blob/main/opentelemetry/src/propagation/mod.rs>
use std::collections::HashMap;

use crate::error::Error;

/// Injector provides an interface for a carrier to be used
/// with a Propagator to inject a Context into the carrier.
pub trait Injector {
    /// Set a value in the carrier.
    fn set(&mut self, key: &str, value: String);
}

pub trait Extractor {
    /// Get a value from the carrier.
    fn get(&self, key: &str) -> Option<&str>;

    /// Get all values for a key from the carrier
    fn get_all(&self, key: &str) -> Option<Vec<&str>>;

    /// Get all keys from the carrier.
    fn keys(&self) -> Vec<&str>;
}

pub fn get_single_value_from_extractor<'a>(
    extractor: &'a dyn Extractor,
    key: &'a str,
) -> Result<Option<&'a str>, Error> {
    let all = extractor.get_all(key);
    if let Some(all) = all {
        if all.iter().len() > 1 {
            return Err(Error::extract(
                "Multiple values while getting a single value",
                "generic",
            ));
        } else {
            return Ok(all.first().map(|v| &**v));
        }
    }

    Ok(None)
}

pub fn get_comma_separated_value_from_extractor<'a>(
    extractor: &'a dyn Extractor,
    key: &'a str,
) -> Option<String> {
    extractor.get_all(key).map(|all| {
        all.iter()
            .filter(|part| !part.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(",")
    })
}

impl<S: std::hash::BuildHasher> Injector for HashMap<String, String, S> {
    /// Set a key and value in the `HashMap`.
    fn set(&mut self, key: &str, value: String) {
        self.insert(key.to_lowercase(), value);
    }
}

impl<S: std::hash::BuildHasher> Extractor for HashMap<String, String, S> {
    /// Get a value for a key from the `HashMap`.
    fn get(&self, key: &str) -> Option<&str> {
        self.get(&key.to_lowercase()).map(String::as_str)
    }

    /// Get all values for a key from the `HashMap`.
    fn get_all(&self, key: &str) -> Option<Vec<&str>> {
        Extractor::get(self, key).map(|value| vec![value])
    }

    /// Collect all the keys from the `HashMap`.
    fn keys(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect::<Vec<_>>()
    }
}

#[cfg(feature = "opentelemetry")]
impl Extractor for &dyn opentelemetry::propagation::Extractor {
    fn get(&self, key: &str) -> Option<&str> {
        opentelemetry::propagation::Extractor::get(*self, key)
    }

    fn get_all(&self, key: &str) -> Option<Vec<&str>> {
        opentelemetry::propagation::Extractor::get_all(*self, key)
    }

    fn keys(&self) -> Vec<&str> {
        opentelemetry::propagation::Extractor::keys(*self)
    }
}

#[cfg(feature = "opentelemetry")]
impl Injector for &mut dyn opentelemetry::propagation::Injector {
    fn set(&mut self, key: &str, value: String) {
        opentelemetry::propagation::Injector::set(*self, key, value);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hash_map_get() {
        let mut carrier = HashMap::new();
        carrier.set("headerName", "value".to_string());

        assert_eq!(
            Extractor::get(&carrier, "HEADERNAME"),
            Some("value"),
            "case insensitive extraction"
        );
    }

    #[test]
    fn hash_map_keys() {
        let mut carrier = HashMap::new();
        carrier.set("headerName1", "value1".to_string());
        carrier.set("headerName2", "value2".to_string());

        let got = Extractor::keys(&carrier);
        assert_eq!(got.len(), 2);
        assert!(got.contains(&"headername1"));
        assert!(got.contains(&"headername2"));
    }
}

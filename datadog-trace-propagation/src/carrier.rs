// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Carrier traits for trace context propagation.
//!
//! This module provides the [`Injector`] trait for injecting trace context
//! into carriers (e.g., HTTP headers), with implementations for common types
//! like [`HashMap`] and OpenTelemetry's propagation traits.
//!
//! Code inspired by the OpenTelemetry Rust project.
//! <https://github.com/open-telemetry/opentelemetry-rust/blob/main/opentelemetry/src/propagation/mod.rs>

use std::collections::HashMap;

/// Injector provides an interface for a carrier to be used
/// with a Propagator to inject a Context into the carrier.
pub trait Injector {
    /// Set a value in the carrier.
    fn set(&mut self, key: &str, value: String);
}

/// Extractor provides an interface for a carrier to be used
/// with a Propagator to extract a Context from the carrier.
pub trait Extractor {
    /// Get a value from the carrier by key.
    fn get(&self, key: &str) -> Option<&str>;

    /// Get all keys from the carrier.
    #[allow(unused)]
    fn keys(&self) -> Vec<&str>;
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

    /// Collect all the keys from the `HashMap`.
    fn keys(&self) -> Vec<&str> {
        self.keys().map(String::as_str).collect::<Vec<_>>()
    }
}

impl Extractor for &dyn opentelemetry::propagation::Extractor {
    fn get(&self, key: &str) -> Option<&str> {
        opentelemetry::propagation::Extractor::get(*self, key)
    }

    fn keys(&self) -> Vec<&str> {
        opentelemetry::propagation::Extractor::keys(*self)
    }
}

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

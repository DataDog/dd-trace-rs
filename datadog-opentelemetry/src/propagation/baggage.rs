// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! W3C Baggage propagation (`baggage` header).
//!
//! Actual extract/inject is performed by [`opentelemetry_sdk::propagation::BaggagePropagator`]
//! at the [`DatadogPropagator`](crate::text_map_propagator::DatadogPropagator) layer, which has
//! access to the OTel [`Context`](opentelemetry::Context) that carries baggage. This module
//! exposes the header key so the composite propagator can include it in its `fields()` list.

use std::sync::LazyLock;

/// The W3C `baggage` header name.
pub const BAGGAGE_KEY: &str = "baggage";

static BAGGAGE_HEADER_KEYS: LazyLock<[String; 1]> = LazyLock::new(|| [BAGGAGE_KEY.to_owned()]);

/// Returns the header keys used by the W3C baggage propagator.
pub fn keys() -> &'static [String] {
    BAGGAGE_HEADER_KEYS.as_slice()
}

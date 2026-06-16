// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::TracePropagationStyle;
use serde::{Deserialize, Deserializer};

use crate::propagation::{
    baggage,
    carrier::{Extractor, Injector},
    context::{InjectSpanContext, SpanContext},
    datadog, tracecontext, PropagationConfig, Propagator,
};

const NONE_KEYS: [String; 0] = [];

impl<C: PropagationConfig + ?Sized> Propagator<C> for TracePropagationStyle {
    fn extract(&self, carrier: &dyn Extractor, config: &C) -> Option<SpanContext> {
        match self {
            Self::Datadog => datadog::extract(carrier, config),
            Self::TraceContext => tracecontext::extract(carrier),
            // Baggage extraction operates on OTel Context and is handled by DatadogPropagator.
            Self::Baggage | Self::None => None,
            // B3 propagators are wired in subsequent changes.
            Self::B3Multi | Self::B3SingleHeader => None,
        }
    }

    fn inject(&self, context: &mut InjectSpanContext, carrier: &mut dyn Injector, config: &C) {
        match self {
            Self::Datadog => datadog::inject(context, carrier, config),
            Self::TraceContext => tracecontext::inject(context, carrier),
            // Baggage injection operates on OTel Context and is handled by DatadogPropagator.
            Self::Baggage | Self::None => {}
            // B3 propagators are wired in subsequent changes.
            Self::B3Multi | Self::B3SingleHeader => {}
        }
    }

    fn keys(&self) -> &[String] {
        match self {
            Self::Datadog => datadog::keys(),
            Self::TraceContext => tracecontext::keys(),
            Self::Baggage => baggage::keys(),
            Self::None | Self::B3Multi | Self::B3SingleHeader => &NONE_KEYS,
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[allow(unused)]
pub fn deserialize_trace_propagation_style<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<TracePropagationStyle>>, D::Error>
where
    D: Deserializer<'de>,
{
    use std::str::FromStr;

    let s: String = String::deserialize(deserializer)?;

    if s.is_empty() {
        Ok(None)
    } else {
        let styles = s
            .split(',')
            .filter_map(|style| {
                TracePropagationStyle::from_str(style.trim())
                    .map_err(|e| {
                        <serde_json::Error as serde::de::Error>::custom(format!(
                            "Failed to deserialize propagation style: {e}"
                        ))
                    })
                    .ok()
            })
            .collect();

        Ok(Some(styles))
    }
}

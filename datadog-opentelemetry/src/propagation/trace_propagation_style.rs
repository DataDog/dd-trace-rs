// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::TracePropagationStyle;
use serde::{Deserialize, Deserializer};

use crate::propagation::{
    b3, b3multi, baggage,
    carrier::{Extractor, Injector},
    context::{InjectSpanContext, SpanContext},
    datadog,
    error::Error,
    tracecontext, PropagationConfig, Propagator,
};

const NONE_KEYS: [String; 0] = [];

impl<C: PropagationConfig + ?Sized> Propagator<C> for TracePropagationStyle {
    fn try_extract(
        &self,
        carrier: &dyn Extractor,
        config: &C,
    ) -> Option<Result<SpanContext, Error>> {
        match self {
            Self::Datadog => datadog::try_extract(carrier, config),
            Self::TraceContext => tracecontext::try_extract(carrier),
            // b3/b3multi don't distinguish malformed from absent — both already log via
            // `dd_warn!` and return `None`.
            Self::B3Multi => b3multi::extract(carrier).map(Ok),
            Self::B3SingleHeader => b3::extract(carrier).map(Ok),
            // Baggage extraction operates on OTel Context and is handled by DatadogPropagator.
            Self::Baggage | Self::None => None,
        }
    }

    fn inject(&self, context: &mut InjectSpanContext, carrier: &mut dyn Injector, config: &C) {
        match self {
            Self::Datadog => datadog::inject(context, carrier, config),
            Self::TraceContext => tracecontext::inject(context, carrier),
            Self::B3Multi => b3multi::inject(context, carrier),
            Self::B3SingleHeader => b3::inject(context, carrier),
            // Baggage injection operates on OTel Context and is handled by DatadogPropagator.
            Self::Baggage | Self::None => {}
        }
    }

    fn keys(&self) -> &[String] {
        match self {
            Self::Datadog => datadog::keys(),
            Self::TraceContext => tracecontext::keys(),
            Self::B3Multi => b3multi::keys(),
            Self::B3SingleHeader => b3::keys(),
            Self::Baggage => baggage::keys(),
            Self::None => &NONE_KEYS,
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

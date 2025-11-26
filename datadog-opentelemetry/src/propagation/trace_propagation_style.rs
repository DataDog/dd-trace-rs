// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::{Config, TracePropagationStyle};
use serde::{Deserialize, Deserializer};

use super::{
    carrier::{Extractor, Injector},
    context::{InjectSpanContext, SpanContext},
    datadog, tracecontext, Propagator,
};

const NONE_KEYS: [String; 0] = [];

impl Propagator for TracePropagationStyle {
    fn extract(&self, carrier: &dyn Extractor, config: &Config) -> Option<SpanContext> {
        match self {
            Self::Datadog => datadog::extract(carrier, config),
            Self::TraceContext => tracecontext::extract(carrier),
            _ => None,
        }
    }

    fn inject(&self, context: &mut InjectSpanContext, carrier: &mut dyn Injector, config: &Config) {
        match self {
            Self::Datadog => datadog::inject(context, carrier, config),
            Self::TraceContext => tracecontext::inject(context, carrier),
            _ => {}
        }
    }

    fn keys(&self) -> &[String] {
        match self {
            Self::Datadog => datadog::keys(),
            Self::TraceContext => tracecontext::keys(),
            _ => &NONE_KEYS,
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

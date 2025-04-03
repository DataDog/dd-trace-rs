// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::trace_propagation_style::TracePropagationStyle;

#[cfg(feature = "serde_config")]
use crate::trace_propagation_style::deserialize_trace_propagation_style;

#[cfg(feature = "serde_config")]
use serde::Deserialize;

#[cfg(not(feature = "serde_config"))]
#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    // Trace Propagation
    pub trace_propagation_style: Vec<TracePropagationStyle>,
    pub trace_propagation_style_extract: Vec<TracePropagationStyle>,
    pub trace_propagation_extract_first: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // Trace Propagation
            trace_propagation_style: vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ],
            trace_propagation_style_extract: vec![],
            trace_propagation_extract_first: false,
        }
    }
}

#[cfg(feature = "serde_config")]
#[derive(Debug, PartialEq, Deserialize, Clone)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    // Trace Propagation
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub trace_propagation_style: Vec<TracePropagationStyle>,
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub trace_propagation_style_extract: Vec<TracePropagationStyle>,
    pub trace_propagation_extract_first: bool,
}

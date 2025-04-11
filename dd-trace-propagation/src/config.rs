// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;

use crate::trace_propagation_style::TracePropagationStyle;

#[cfg(feature = "serde_config")]
use crate::trace_propagation_style::deserialize_trace_propagation_style;

#[cfg(feature = "serde_config")]
use serde::Deserialize;

lazy_static! {
    pub static ref DEFAULT_PROPAGATION_STYLES: Vec<TracePropagationStyle> = vec![
        TracePropagationStyle::Datadog,
        TracePropagationStyle::TraceContext,
    ];
}

#[cfg(not(feature = "serde_config"))]
#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
pub struct Config {
    // Trace Propagation
    pub trace_propagation_style: Option<Vec<TracePropagationStyle>>,
    pub trace_propagation_style_extract: Option<Vec<TracePropagationStyle>>,
    pub trace_propagation_style_inject: Option<Vec<TracePropagationStyle>>,
    pub trace_propagation_extract_first: bool,
}

impl Config {
    pub fn get_extractors(&self) -> &Vec<TracePropagationStyle> {
        if let Some(extractors) = &self.trace_propagation_style_extract {
            extractors
        } else if let Some(styles) = &self.trace_propagation_style {
            styles
        } else {
            &DEFAULT_PROPAGATION_STYLES
        }
    }

    pub fn get_injectors(&self) -> &Vec<TracePropagationStyle> {
        if let Some(injectors) = &self.trace_propagation_style_inject {
            injectors
        } else if let Some(styles) = &self.trace_propagation_style {
            styles
        } else {
            &DEFAULT_PROPAGATION_STYLES
        }
    }
}

#[cfg(feature = "serde_config")]
#[derive(Debug, PartialEq, Deserialize, Clone)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
pub struct Config {
    // Trace Propagation
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub trace_propagation_style: Option<Vec<TracePropagationStyle>>,
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub trace_propagation_style_extract: Option<Vec<TracePropagationStyle>>,
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub trace_propagation_style_inject: Option<Vec<TracePropagationStyle>>,
    pub trace_propagation_extract_first: bool,
}

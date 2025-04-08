// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::{configuration::TracePropagationStyle, Config};
use lazy_static::lazy_static;

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
pub struct PropagationConfig {
    pub style: Option<Vec<TracePropagationStyle>>,
    pub style_extract: Option<Vec<TracePropagationStyle>>,
    pub style_inject: Option<Vec<TracePropagationStyle>>,
    pub extract_first: bool,
}

impl PropagationConfig {
    pub fn from(config: &Config) -> Self {
        PropagationConfig {
            style: config
                .trace_propagation_style()
                .map(<[TracePropagationStyle]>::to_vec),
            style_extract: config
                .trace_propagation_style_extract()
                .map(<[TracePropagationStyle]>::to_vec),
            style_inject: config
                .trace_propagation_style_inject()
                .map(<[TracePropagationStyle]>::to_vec),
            extract_first: config.trace_propagation_extract_first(),
        }
    }

    pub fn get_extractors(&self) -> &Vec<TracePropagationStyle> {
        if let Some(extractors) = &self.style_extract {
            extractors
        } else if let Some(styles) = &self.style {
            styles
        } else {
            &DEFAULT_PROPAGATION_STYLES
        }
    }

    pub fn get_injectors(&self) -> &Vec<TracePropagationStyle> {
        if let Some(injectors) = &self.style_inject {
            injectors
        } else if let Some(styles) = &self.style {
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
pub struct PropagationConfig {
    // Trace Propagation
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub style: Option<Vec<TracePropagationStyle>>,
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub style_extract: Option<Vec<TracePropagationStyle>>,
    #[serde(deserialize_with = "deserialize_trace_propagation_style")]
    pub style_inject: Option<Vec<TracePropagationStyle>>,
    pub extract_first: bool,
}

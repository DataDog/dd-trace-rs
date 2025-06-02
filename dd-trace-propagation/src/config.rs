// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::{configuration::TracePropagationStyle, Config};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_PROPAGATION_STYLES: Vec<TracePropagationStyle> = vec![
        TracePropagationStyle::Datadog,
        TracePropagationStyle::TraceContext,
    ];
}

pub fn get_extractors(config: &Config) -> &[TracePropagationStyle] {
    if let Some(extractors) = config.trace_propagation_style_extract() {
        extractors
    } else if let Some(styles) = &config.trace_propagation_style() {
        styles
    } else {
        &DEFAULT_PROPAGATION_STYLES
    }
}

pub fn get_injectors(config: &Config) -> &[TracePropagationStyle] {
    if let Some(injectors) = config.trace_propagation_style_inject() {
        injectors
    } else if let Some(styles) = config.trace_propagation_style() {
        styles
    } else {
        &DEFAULT_PROPAGATION_STYLES
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::{configuration::TracePropagationStyle, Config};

pub fn get_extractors(config: &Config) -> &[TracePropagationStyle] {
    if let Some(extractors) = config.trace_propagation_style_extract() {
        extractors
    } else {
        config.trace_propagation_style().unwrap_or_default()
    }
}

pub fn get_injectors(config: &Config) -> &[TracePropagationStyle] {
    if let Some(injectors) = config.trace_propagation_style_inject() {
        injectors
    } else {
        config.trace_propagation_style().unwrap_or_default()
    }
}

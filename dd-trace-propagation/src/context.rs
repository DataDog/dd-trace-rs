// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

#[derive(Copy, Clone, Default, Debug, PartialEq)]
pub struct Sampling {
    pub priority: Option<i8>,
    pub mechanism: Option<u8>,
}

#[derive(Clone, Default, Debug, PartialEq)]
pub struct SpanLink {
    pub trace_id: u64,
    pub trace_id_high: Option<u64>,
    pub span_id: u64,
    pub attributes: Option<HashMap<String, String>>,
    pub tracestate: Option<String>,
    pub flags: Option<u32>,
}

#[derive(Clone, Default, Debug, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub struct SpanContext {
    pub trace_id: u64,
    pub span_id: u64,
    pub sampling: Option<Sampling>,
    pub origin: Option<String>,
    pub tags: HashMap<String, String>,
    pub links: Vec<SpanLink>,
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub const HIGHER_ORDER_TRACE_ID_BITS_TAG: &str = "_dd.p.tid";
pub const SPAN_KIND_TAG: &str = "span.kind";
pub const SAMPLING_PRIORITY_TAG: &str = "_sampling_priority_v1";
pub const SAMPLING_RATE_EVENT_EXTRACTION: &str = "_dd1.sr.eausr";

pub const SAMPLING_DECISION_AUTO_DROP: i32 = 0;
pub const SAMPLING_DECISION_AUTO_KEEP: i32 = 1;
pub const SAMPLING_DECISION_MANUAL_DROP: i32 = -1;
pub const SAMPLING_DECISION_MANUAL_KEEP: i32 = 2;

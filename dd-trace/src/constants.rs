// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub const HIGHER_ORDER_TRACE_ID_BITS_TAG: &str = "_dd.p.tid";

pub const SPAN_KIND_TAG: &str = "span.kind";

pub const SAMPLING_RATE_EVENT_EXTRACTION_KEY: &str = "_dd1.sr.eausr";

pub const SAMPLING_PRIORITY_TAG_KEY: &str = "_sampling_priority_v1";

pub const SAMPLING_DECISION_MAKER_TAG_KEY: &str = "_dd.p.dm";

pub const SAMPLING_RULE_RATE_TAG_KEY: &str = "_dd.rule.psr";

pub const SAMPLING_AGENT_RATE_TAG_KEY: &str = "_dd.agent_psr";

pub const RL_EFFECTIVE_RATE: &str = "_dd.limit_psr";

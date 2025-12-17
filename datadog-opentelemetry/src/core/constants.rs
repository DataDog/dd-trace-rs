// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[allow(unused)]
pub(crate) const HIGHER_ORDER_TRACE_ID_BITS_TAG: &str = "_dd.p.tid";

#[allow(unused)]
pub(crate) const SPAN_KIND_TAG: &str = "span.kind";

pub(crate) const SAMPLING_RATE_EVENT_EXTRACTION_KEY: &str = "_dd1.sr.eausr";

pub(crate) const SAMPLING_PRIORITY_TAG_KEY: &str = "_sampling_priority_v1";

pub(crate) const SAMPLING_DECISION_MAKER_TAG_KEY: &str = "_dd.p.dm";

pub(crate) const SAMPLING_RULE_RATE_TAG_KEY: &str = "_dd.rule_psr";

pub(crate) const SAMPLING_AGENT_RATE_TAG_KEY: &str = "_dd.agent_psr";

pub(crate) const RL_EFFECTIVE_RATE: &str = "_dd.limit_psr";

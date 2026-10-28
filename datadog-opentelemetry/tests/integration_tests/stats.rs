// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use datadog_opentelemetry::configuration::Config;
use opentelemetry::trace::{SpanBuilder, TracerProvider};

use crate::integration_tests::with_test_agent_session;

// Verify that client-side stats keys beyond the whole-key cardinality limit
// (`DD_TRACE_STATS_CARDINALITY_LIMIT`, wired through
// `ConfigBuilder::set_trace_stats_cardinality_limit`) are folded into the
// `tracer_blocked_value` overflow bucket.
//
// The limit is set very low on purpose: the first distinct aggregation keys are kept
// as-is while every further key is collapsed into the sentinel overflow bucket whose
// hits reflect the folded spans. The trace-stats snapshot must therefore contain the
// kept buckets plus exactly one folded bucket identified by the `tracer_blocked_value`
// sentinel values.
#[tokio::test]
async fn test_stats_cardinality_limit_folds_overflow_buckets() {
    const SESSION_NAME: &str = "opentelemetry_api/test_stats_cardinality_limit";
    let mut cfg = Config::builder();
    // Only two distinct stats keys are admitted; anything beyond folds into the
    // overflow bucket.
    cfg.set_trace_stats_cardinality_limit(2);
    with_test_agent_session(SESSION_NAME, cfg, |_, tracer_provider, _, _| {
        let tracer = tracer_provider.tracer("test");

        for span_name in ["stats-op-1", "stats-op-2", "stats-op-3", "stats-op-4"] {
            // Each span is a distinct trace root with a distinct resource (defaulting to
            // the span name), hence a distinct stats aggregation key. Spans are
            // processed in creation order, so `stats-op-1` and `stats-op-2` are kept
            // while `stats-op-3` and `stats-op-4` fold into the overflow bucket.
            drop(
                SpanBuilder::from_name(span_name)
                    .with_kind(opentelemetry::trace::SpanKind::Client)
                    .start_with_context(&tracer, &opentelemetry::Context::new()),
            );
        }
    })
    .await;
}

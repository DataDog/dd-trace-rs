// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

#[allow(dead_code)]
fn test_span_data(
    trace_flags: opentelemetry::TraceFlags,
    trace_id: opentelemetry::TraceId,
) -> Vec<opentelemetry_sdk::trace::SpanData> {
    // unix epoch + 30 years puts us in the 2000s :wink:
    let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(60 * 60 * 24 * 365 * 31);
    (1..2)
        .map(|i| opentelemetry_sdk::trace::SpanData {
            span_context: opentelemetry::trace::SpanContext::new(
                trace_id,
                opentelemetry::SpanId::from_bytes([i; 8]),
                trace_flags,
                false,
                opentelemetry::trace::TraceState::default(),
            ),
            parent_span_id: opentelemetry::SpanId::from_bytes([i - 1; 8]),
            span_kind: opentelemetry::trace::SpanKind::Client,
            name: std::borrow::Cow::Borrowed("test"),
            start_time: now,
            end_time: now + Duration::from_millis(100),
            attributes: vec![],
            dropped_attributes_count: 0,
            events: opentelemetry_sdk::trace::SpanEvents::default(),
            links: opentelemetry_sdk::trace::SpanLinks::default(),
            status: opentelemetry::trace::Status::Ok,
            instrumentation_scope: opentelemetry::InstrumentationScope::builder("test").build(),
        })
        .collect()
}

#[cfg(not(windows))]
mod datadog_test_agent {
    use datadog_opentelemetry::DatadogExporter;
    use datadog_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent;
    use opentelemetry::{TraceFlags, TraceId};
    use opentelemetry_sdk::trace::SpanExporter;

    use crate::test_span_data;

    #[tokio::test]
    // #[cfg_attr(miri, ignore)]
    async fn test_received_traces() {
        const SESSION_NAME: &str = "test_received_traces";

        let relative_snapshot_path = "datadog-opentelemetry/tests/snapshots/";
        let test_agent =
            DatadogTestAgent::new_create_snapshot(Some(relative_snapshot_path), None).await;
        let url = test_agent.get_base_uri().await;
        test_agent.start_session(SESSION_NAME, None).await;

        let mut config = dd_trace::Config::builder();
        config.set_trace_agent_url(url.to_string().into());
        let mut exporter = DatadogExporter::new(config.build()).unwrap();

        let mut span_data = test_span_data(
            TraceFlags::SAMPLED,
            TraceId::from_bytes(u128::to_be_bytes(1234)),
        );
        span_data.extend(test_span_data(
            TraceFlags::NOT_SAMPLED,
            TraceId::from_bytes([2; 16]),
        ));

        exporter.export(span_data).await.unwrap();
        exporter.shutdown().unwrap();

        test_agent.assert_snapshot(SESSION_NAME).await;
    }
}

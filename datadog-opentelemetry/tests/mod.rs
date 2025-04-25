// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(windows))]
mod datadog_test_agent {
    use datadog_opentelemetry::make_tracer;
    use datadog_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent;
    use opentelemetry::trace::{
        SamplingDecision, SamplingResult, SpanBuilder, TraceState, TracerProvider,
    };
    use opentelemetry::Context;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_received_traces() {
        const SESSION_NAME: &str = "test_received_traces";

        let relative_snapshot_path = "datadog-opentelemetry/tests/snapshots/";
        let test_agent =
            DatadogTestAgent::new_create_snapshot(Some(relative_snapshot_path), None).await;
        let url = test_agent.get_base_uri().await;
        test_agent.start_session(SESSION_NAME, None).await;

        let mut config = dd_trace::Config::builder();
        config.set_trace_agent_url(url.to_string().into());

        let tracer_provider = make_tracer(
            config.build(),
            opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        );
        let tracer = tracer_provider.tracer("test");
        for decision in [
            SamplingDecision::RecordOnly,
            SamplingDecision::RecordAndSample,
        ] {
            {
                let base_ctx = Context::new();
                let span = SpanBuilder::from_name("test")
                    .with_kind(opentelemetry::trace::SpanKind::Client)
                    .with_sampling_result(SamplingResult {
                        decision,
                        attributes: vec![],
                        trace_state: TraceState::default(),
                    })
                    .start_with_context(&tracer, &base_ctx);
                drop(span)
            };
        }

        tracer_provider.shutdown().expect("failed to shutdown");

        test_agent.assert_snapshot(SESSION_NAME).await;
    }
}

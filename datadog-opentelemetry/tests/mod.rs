// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(windows))]
mod datadog_test_agent {
    use std::{
        collections::{HashMap, HashSet},
        fmt,
        hash::{Hash, RandomState},
        ops::Deref,
        sync::Arc,
    };

    use datadog_opentelemetry::make_test_tracer;
    use datadog_trace_utils::test_utils::datadog_test_agent::DatadogTestAgent;
    use dd_trace::configuration::{SamplingRuleConfig, TracePropagationStyle};
    use opentelemetry::global::ObjectSafeSpan;
    use opentelemetry::trace::{
        SamplingDecision, SamplingResult, SpanBuilder, TraceContextExt, TraceState, TracerProvider,
    };
    use opentelemetry::{propagation::Extractor, propagation::TextMapPropagator, Context};

    fn make_extractor<I: IntoIterator<Item = (&'static str, &'static str)>>(
        headers: I,
    ) -> impl Extractor + Send + Sync {
        HashMap::<_, _, RandomState>::from_iter(
            headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        )
    }

    async fn make_test_agent(session_name: &'static str) -> DatadogTestAgent {
        let relative_snapshot_path = "datadog-opentelemetry/tests/snapshots/";
        let test_agent = DatadogTestAgent::new(
            Some(relative_snapshot_path),
            None,
            &[
                ("SNAPSHOT_CI", "0"),
                (
                    "SNAPSHOT_IGNORED_ATTRS",
                    "span_id,trace_id,parent_id,duration,start,meta.otel.trace_id",
                ),
            ],
        )
        .await;
        test_agent.start_session(session_name, None).await;
        test_agent
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_received_traces() {
        const SESSION_NAME: &str = "test_received_traces";
        let test_agent = make_test_agent(SESSION_NAME).await;

        let mut config_builder = dd_trace::Config::builder();
        config_builder.set_trace_agent_url(test_agent.get_base_uri().await.to_string().into());
        let config = Arc::new(config_builder.build());

        let tracer_provider = make_test_tracer(
            config,
            opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        )
        .0;
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

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_injection_extraction() {
        const SESSION_NAME: &str = "test_injection_extraction";
        let test_agent = make_test_agent(SESSION_NAME).await;

        let mut config_builder = dd_trace::Config::builder();
        config_builder.set_trace_agent_url(test_agent.get_base_uri().await.to_string().into());
        let config = Arc::new(config_builder.build());

        let (tracer_provider, propagator) = make_test_tracer(
            config,
            opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        );

        let parent_ctx = propagator.extract(&make_extractor([
            (
                "traceparent",
                "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01",
            ),
            ("tracestate", "dd=p:00f067aa0ba902b7;s:2;o:rum"),
        ]));
        let _guard = parent_ctx.attach();

        let mut injected = HashMap::new();

        let tracer = tracer_provider.tracer("test");
        {
            let span = SpanBuilder::from_name("test_parent")
                .with_kind(opentelemetry::trace::SpanKind::Server)
                .start(&tracer);
            let _ctx = Context::current_with_span(span).attach();
            {
                let child_span = SpanBuilder::from_name("test_child")
                    .with_kind(opentelemetry::trace::SpanKind::Client)
                    .start(&tracer);
                let _child_ctx = Context::current_with_span(child_span).attach();

                propagator.inject(&mut injected);
            }
        }

        assert_subset(
            injected.iter().map(|(k, v_)| (k.as_str(), v_.as_str())),
            [
                ("x-datadog-origin", "rum"),
                ("x-datadog-sampling-priority", "2"),
                ("x-datadog-trace-id", "7277407061855694839"),
            ],
        );

        assert_subset(
            injected.get("x-datadog-tags").unwrap().split(','),
            ["_dd.p.dm=-0"],
        );

        assert_subset(
            injected
                .get("tracestate")
                .unwrap()
                .strip_prefix("dd=")
                .unwrap()
                .split(';'),
            ["s:2", "o:rum", "t.tid:80f198ee56343ba8", "t.dm:-0"],
        );
        assert_subset(
            injected
                .get("traceparent")
                .unwrap()
                .strip_prefix("00-")
                .unwrap()
                .splitn(3, '-'),
            ["01", "80f198ee56343ba864fe8b2a57d3eff7"],
        );

        tracer_provider.shutdown().expect("failed to shutdown");
        test_agent.assert_snapshot(SESSION_NAME).await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_sampling_extraction() {
        const SESSION_NAME: &str = "test_sampling_extraction";
        let test_agent = make_test_agent(SESSION_NAME).await;

        let mut config_builder = dd_trace::Config::builder();
        config_builder.set_trace_agent_url(test_agent.get_base_uri().await.to_string().into());
        config_builder.set_service("my_service_name".to_string());
        config_builder.set_trace_sampling_rules(vec![SamplingRuleConfig {
            service: Some("my_service_name".to_string()),
            sample_rate: 1.0,
            ..SamplingRuleConfig::default()
        }]);
        config_builder.set_trace_propagation_style(vec![TracePropagationStyle::TraceContext]);
        let config = Arc::new(config_builder.build());

        let (tracer_provider, propagator) = make_test_tracer(
            config,
            opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        );

        let mut injected = HashMap::new();
        let trace_id;
        let span_id;
        let tracer = tracer_provider.tracer("test");
        {
            let span = SpanBuilder::from_name("test_parent")
                .with_kind(opentelemetry::trace::SpanKind::Server)
                .start(&tracer);
            let _ctx: opentelemetry::ContextGuard = Context::current_with_span(span).attach();
            {
                let child_span = SpanBuilder::from_name("test_child")
                    .with_kind(opentelemetry::trace::SpanKind::Client)
                    .start(&tracer);
                trace_id = child_span.span_context().trace_id();
                span_id = child_span.span_context().span_id();

                let _child_ctx = Context::current_with_span(child_span).attach();

                propagator.inject(&mut injected);
            }
        }
        tracer_provider.shutdown().expect("failed to shutdown");
        test_agent.assert_snapshot(SESSION_NAME).await;

        assert_subset(
            injected
                .get("tracestate")
                .unwrap()
                .strip_prefix("dd=")
                .unwrap()
                .split(';')
                .map(String::from),
            [
                "s:2".to_string(),
                "t.dm:-3".to_string(),
                format!("p:{span_id:016x}"),
            ],
        );

        assert_subset(
            injected.into_iter(),
            [(
                "traceparent".to_string(),
                format!("00-{trace_id:032x}-{span_id:016x}-01"),
            )],
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_remote_config_sampling_rates() {
        const SESSION_NAME: &str = "test_remote_config_sampling_rates";
        let test_agent = make_test_agent(SESSION_NAME).await;

        test_agent
            .set_remote_config_response(
                r##"{
            "path": "datadog/2/APM_TRACING/1234/config",
            "msg": {
                "tracing_sampling_rules": [
                    {
                        "resource": "test-span",
                        "sample_rate": 1.0,
                        "provenance": "customer"
                    }
                ]
            }
        }"##,
                None,
            )
            .await;

        let config = dd_trace::Config::builder()
            .set_trace_agent_url(test_agent.get_base_uri().await.to_string().into())
            .set_trace_sampling_rules(vec![dd_trace::SamplingRuleConfig {
                resource: Some("test-span".into()),
                sample_rate: 0.0,
                ..Default::default()
            }])
            .set_log_level_filter(dd_trace::log::LevelFilter::Debug)
            .build();
        let config = Arc::new(config);

        let (tracer_provider, _propagator) = make_test_tracer(
            config.clone(),
            opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        );
        // Wait for the config to be applied
        // TODO(paullgdc): If this test is flaky this is probably it, fetching the config took more
        // than 2 seconds  We should probably have a way to sleep until the config is
        // applied, but this is a bit convoluted
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        assert_eq!(
            config.trace_sampling_rules().deref(),
            vec![dd_trace::SamplingRuleConfig {
                resource: Some("test-span".into()),
                sample_rate: 1.0,
                provenance: "customer".into(),
                ..Default::default()
            }]
        );

        drop(SpanBuilder::from_name("test-span").start(&tracer_provider.tracer("test")));

        tracer_provider.shutdown().expect("failed to shutdown");
        test_agent.assert_snapshot(SESSION_NAME).await;
    }

    #[track_caller]
    fn assert_subset<I, S: IntoIterator<Item = I>, SS: IntoIterator<Item = I>>(set: S, subset: SS)
    where
        I: Hash + Eq + fmt::Debug,
    {
        let set: HashSet<_, RandomState> = HashSet::from_iter(set);
        for item in subset {
            if !set.contains(&item) {
                panic!("Set {set:?} does not contain subset item {item:?}");
            }
        }
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use axum::{body::to_bytes, http::Method, Router};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use opentelemetry::{
    global::{self},
    trace::{SpanKind, Tracer},
};
use tokio::runtime::Runtime;

use crate::axum_servers::{DatadogServer, OpenTelemetryServer};

mod axum_servers {
    use axum::{
        extract::Request,
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{get, post},
        Router,
    };
    use opentelemetry::{
        global::{self},
        trace::{FutureExt, SpanKind, TraceContextExt, Tracer},
        Context, KeyValue,
    };
    use opentelemetry_http::HeaderExtractor;
    use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use std::time::{Duration, Instant};
    use tower::ServiceBuilder;
    use tower_http::trace::TraceLayer;

    // OpenTelemetry server setup
    pub struct OpenTelemetryServer {
        pub tracer_provider: SdkTracerProvider,
        pub router: Router,
    }

    impl OpenTelemetryServer {
        pub fn new() -> Self {
            let exporter = SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary) //can be changed to `Protocol::HttpJson` to export in JSON format
                .build()
                .expect("Failed to create trace exporter");

            let tracer_provider = SdkTracerProvider::builder()
                /* .with_resource(Resource::new([
                    opentelemetry::KeyValue::new("service.name", "otel-bench-server"),
                    opentelemetry::KeyValue::new("service.version", "1.0.0"),
                ])) */
                .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
                .with_batch_exporter(exporter)
                .build();

            global::set_tracer_provider(tracer_provider.clone());

            let router = Router::new()
                .route("/health", get(health_handler))
                .route("/echo", post(echo_handler))
                .route("/compute", get(compute_handler))
                .route("/nested", get(nested_handler))
                .layer(
                    ServiceBuilder::new()
                        .layer(middleware::from_fn(tracing_middleware))
                        .layer(TraceLayer::new_for_http()),
                );

            Self {
                tracer_provider,
                router,
            }
        }
    }

    // Datadog server setup
    pub struct DatadogServer {
        pub tracer_provider: opentelemetry_sdk::trace::SdkTracerProvider,
        pub router: Router,
    }

    impl DatadogServer {
        pub fn new(agent_uri: Option<String>) -> Self {
            let mut config = dd_trace::Config::builder();
            config
                .set_service("dd-bench-server".to_string())
                .set_version("1.0.0".to_string());

            if let Some(agent_uri) = agent_uri {
                config.set_trace_agent_url(agent_uri.into());
            }

            let tracer_provider = datadog_opentelemetry::init_datadog(
                config.build(),
                SdkTracerProvider::builder(), // .with_resource(Resource::new([
                                              //     opentelemetry::KeyValue::new("service.name", "dd-bench-server"),
                                              //     opentelemetry::KeyValue::new("service.version", "1.0.0"),
                                              // ]))
            );

            global::set_tracer_provider(tracer_provider.clone());

            let router = Router::new()
                .route("/health", get(health_handler))
                .route("/echo", post(echo_handler))
                .route("/compute", get(compute_handler))
                .route("/nested", get(nested_handler))
                .layer(ServiceBuilder::new().layer(middleware::from_fn(tracing_middleware)));

            Self {
                tracer_provider,
                router,
            }
        }
    }

    // Datadog middleware
    async fn tracing_middleware(request: Request, next: Next) -> Response {
        let start = Instant::now();

        // Extract tracing context from headers
        let parent_cx = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });

        let tracer = global::tracer("axum-server");
        let span = tracer
            .span_builder(format!("{} {}", request.method(), request.uri().path()))
            .with_kind(SpanKind::Server)
            .with_attributes([
                KeyValue::new("http.method", request.method().to_string()),
                KeyValue::new("http.target", request.uri().path().to_string()),
            ])
            .start_with_context(&tracer, &parent_cx);

        let cx = parent_cx.with_span(span);
        let response = next.run(request).with_context(cx).await;

        let duration = start.elapsed();
        Context::current()
            .span()
            .set_attribute(KeyValue::new("duration_ms", duration.as_millis() as i64));

        response
    }

    // Datadog handlers (identical logic, different tracer)
    async fn health_handler() -> impl IntoResponse {
        let tracer = global::tracer("axum-server");
        tracer.in_span("health_check", |_cx| {
            std::thread::sleep(Duration::from_micros(10));
        });

        (StatusCode::OK, "OK")
    }

    async fn echo_handler(body: String) -> impl IntoResponse {
        let tracer = global::tracer("axum-server");
        tracer.in_span("echo_processing", |cx| {
            cx.span()
                .set_attribute(KeyValue::new("body.length", body.len() as i64));
            std::thread::sleep(Duration::from_micros(50));
        });

        body
    }

    async fn compute_handler() -> impl IntoResponse {
        let tracer = global::tracer("axum-server");
        let result = tracer.in_span("compute_operation", |_cx| {
            let mut sum = 0u64;
            for i in 0..10000 {
                sum = sum.wrapping_add(i * i);
            }
            sum
        });

        result.to_string()
    }

    async fn nested_handler() -> impl IntoResponse {
        let tracer = global::tracer("axum-server");
        tracer.in_span("nested_operation", |_cx| {
            tracer.in_span("sub_operation_1", |_cx| {
                std::thread::sleep(Duration::from_micros(20));
            });

            tracer.in_span("sub_operation_2", |_cx| {
                std::thread::sleep(Duration::from_micros(30));
            });
        });

        "nested operations completed"
    }
}

// Benchmark helper functions
async fn simulate_request_otel(
    router: Router,
    path: &str,
    method: &str,
    body: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    let request = Request::builder()
        .uri(path)
        .method(Method::from_bytes(method.as_bytes())?)
        .body(Body::from(body.unwrap_or_default()))?;

    let _response = router.oneshot(request).await?;
    Ok(())
}

async fn simulate_request_datadog(
    router: Router,
    path: &str,
    method: &str,
    body: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use tower::ServiceExt;

    let request = Request::builder()
        .uri(path)
        .method(Method::from_bytes(method.as_bytes())?)
        .body(Body::from(body.unwrap_or_default()))?;

    let _response = router.oneshot(request).await?;
    Ok(())
}

// Benchmark functions
fn bench_health_endpoint(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let otel_server = OpenTelemetryServer::new();
    let dd_server = DatadogServer::new(None);

    let mut group = c.benchmark_group("health_endpoint");

    group.bench_function("opentelemetry", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_otel(
                otel_server.router.clone(),
                black_box("/health"),
                "GET",
                None,
            )
            .await
            .unwrap();
        });
    });

    group.bench_function("datadog", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_datadog(dd_server.router.clone(), black_box("/health"), "GET", None)
                .await
                .unwrap();
        });
    });

    group.finish();
}

fn bench_echo_endpoint(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let medium = "x".repeat(1024);
    let large = "x".repeat(10240);
    let test_bodies = vec![
        ("small", "Hello, World!"),
        ("medium", &medium),
        ("large", &large),
    ];

    let otel_server = OpenTelemetryServer::new();
    let dd_server = DatadogServer::new(None);

    let mut group = c.benchmark_group("echo_endpoint");

    for (size, body) in test_bodies {
        group.bench_with_input(BenchmarkId::new("opentelemetry", size), body, |b, body| {
            b.to_async(&rt).iter(|| async {
                simulate_request_otel(
                    otel_server.router.clone(),
                    black_box("/echo"),
                    "POST",
                    Some(body.to_string()),
                )
                .await
                .unwrap();
            });
        });

        group.bench_with_input(BenchmarkId::new("datadog", size), body, |b, body| {
            b.to_async(&rt).iter(|| async {
                simulate_request_datadog(
                    dd_server.router.clone(),
                    black_box("/echo"),
                    "POST",
                    Some(body.to_string()),
                )
                .await
                .unwrap();
            });
        });
    }

    group.finish();
}

fn bench_compute_endpoint(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let otel_server = OpenTelemetryServer::new();
    let dd_server = DatadogServer::new(None);

    let mut group = c.benchmark_group("compute_endpoint");

    group.bench_function("opentelemetry", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_otel(
                otel_server.router.clone(),
                black_box("/compute"),
                "GET",
                None,
            )
            .await
            .unwrap();
        });
    });

    group.bench_function("datadog", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_datadog(dd_server.router.clone(), black_box("/compute"), "GET", None)
                .await
                .unwrap();
        });
    });

    group.finish();
}

fn bench_nested_spans(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let otel_server = OpenTelemetryServer::new();
    let dd_server = DatadogServer::new(None);

    let mut group = c.benchmark_group("nested_spans");

    group.bench_function("opentelemetry", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_otel(
                otel_server.router.clone(),
                black_box("/nested"),
                "GET",
                None,
            )
            .await
            .unwrap();
        });
    });

    group.bench_function("datadog", |b| {
        b.to_async(&rt).iter(|| async {
            simulate_request_datadog(dd_server.router.clone(), black_box("/nested"), "GET", None)
                .await
                .unwrap();
        });
    });

    group.finish();
}

fn bench_middleware_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let otel_server = OpenTelemetryServer::new();
    let dd_server = DatadogServer::new(None);

    let mut group = c.benchmark_group("middleware_overhead");
    group.significance_level(0.1).sample_size(1000);

    // Test multiple concurrent requests to measure middleware scaling
    let concurrent_requests = vec![1, 5, 10, 20];

    for &concurrency in &concurrent_requests {
        group.bench_with_input(
            BenchmarkId::new("opentelemetry", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| {
                    let router = otel_server.router.clone();
                    async move {
                        let futures: Vec<_> = (0..concurrency)
                            .map(|_| simulate_request_otel(router.clone(), "/health", "GET", None))
                            .collect();

                        futures::future::try_join_all(futures).await.unwrap();
                    }
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("datadog", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| {
                    let router = dd_server.router.clone();
                    async move {
                        let futures: Vec<_> = (0..concurrency)
                            .map(|_| {
                                simulate_request_datadog(router.clone(), "/health", "GET", None)
                            })
                            .collect();

                        futures::future::try_join_all(futures).await.unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_span_creation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("span_creation");

    group.bench_function("opentelemetry_span_creation", |b| {
        let otel_server = axum_servers::OpenTelemetryServer::new();

        b.iter(|| {
            let tracer = global::tracer("benchmark");
            let _span = tracer
                .span_builder(black_box("test_span"))
                .with_kind(SpanKind::Internal)
                .start(&tracer);
        });

        let _ = otel_server.tracer_provider.shutdown();
    });

    group.bench_function("datadog_span_creation", |b| {
        let dd_server = axum_servers::DatadogServer::new(None);

        b.iter(|| {
            let tracer = global::tracer("benchmark");
            let _span = tracer
                .span_builder(black_box("test_span"))
                .with_kind(SpanKind::Internal)
                .start(&tracer);
        });

        let _ = dd_server.tracer_provider.shutdown();
    });

    group.finish();
}

#[ctor::ctor]
fn start_listeners() {
    let listeners = vec![
        ("4318", "Otel Collector"),
        ("8126", "Datadog Agent"),
        // ("8125", "Datadog statsd"),
    ];

    for (port, service) in listeners {
        let t = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                use axum::body::Bytes;
                use axum::extract::Request;
                use axum::{routing::any, Router};
                use std::net::SocketAddr;

                // Handler that prints received requests
                let handle_any = |mut req: Request| {
                    let service = service.to_string();
                    async move {
                        if service.contains("Datadog") {
                            let method = req.method().clone();
                            let uri = req.uri().to_string();
                            let mut body_str = String::new();
                            if method == Method::POST || method == Method::PUT {
                                let bytes = to_bytes(req.into_body(), usize::MAX).await.unwrap();
                                // body_str = String::from_utf8_lossy(&bytes).to_string();
                            }

                            // println!(
                            //     "{} {} {} received body bytes: {:?}",
                            //     service, method, uri, body_str
                            // );
                        }
                        "OK"
                    }
                };

                let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                    .await
                    .unwrap();
                println!(
                    "{} listening on {}",
                    service,
                    listener.local_addr().unwrap()
                );

                let app = Router::new().route("/*path", any(handle_any));
                axum::serve(listener, app).await.unwrap();
            });
        });
    }
}

criterion_group!(
    benches,
    bench_health_endpoint,
    bench_echo_endpoint,
    bench_compute_endpoint,
    bench_nested_spans,
    bench_middleware_overhead,
    bench_span_creation_overhead
);

criterion_main!(benches);

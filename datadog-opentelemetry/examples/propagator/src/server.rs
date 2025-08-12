// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, service::service_fn, HeaderMap, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use opentelemetry::{
    baggage::BaggageExt,
    global::{self, BoxedTracer},
    trace::{FutureExt, Span, SpanKind, TraceContextExt, Tracer},
    Context, InstrumentationScope, KeyValue,
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_http::{Bytes, HeaderExtractor, HeaderInjector};
use opentelemetry_sdk::{
    error::OTelSdkResult,
    logs::{LogProcessor, SdkLogRecord, SdkLoggerProvider},
    trace::{SdkTracerProvider, SpanProcessor},
};
use opentelemetry_semantic_conventions::trace;
use opentelemetry_stdout::{LogExporter, SpanExporter};
use std::{convert::Infallible, net::SocketAddr, sync::OnceLock};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn get_tracer() -> &'static BoxedTracer {
    static TRACER: OnceLock<BoxedTracer> = OnceLock::new();
    TRACER.get_or_init(|| global::tracer("example/server"))
}

// Utility function to extract the context from the incoming request headers
fn extract_context_from_request(req: &Request<Incoming>) -> Context {
    global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    })
}

// Separate async function for the handle endpoint
async fn handle_health_check(
    _req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    let tracer = get_tracer();
    let _span = tracer
        .span_builder("health_check")
        .with_kind(SpanKind::Internal)
        .start(tracer);
    info!(name: "health_check", message = "Health check endpoint hit");

    let res = Response::new(
        Full::new(Bytes::from_static(b"Server is up and running!"))
            .map_err(|err| match err {})
            .boxed(),
    );

    Ok(res)
}

fn foo() {
    get_tracer().in_span("foo", |_cx| {
        println!("foo");
    })
}

fn bar() {
    get_tracer().in_span("bar", |_cx| println!("bar"))
}

fn print_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value:?}"))
        .collect::<Vec<String>>()
        .join(",")
}

// Separate async function for the echo endpoint
async fn handle_echo(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    info!(name: "ECHO: HeadersReceived", headers = print_headers(req.headers()), message = "Response received");

    get_tracer().in_span("echo", |_cx| {
        println!("foo");
        foo();
    });
    info!(name = "echo", message = "Echo endpoint hit");

    let _ = send_request("http://127.0.0.1:3001/cmdi/json", "Jump Request!").await;

    // bar();

    let res = Response::new(req.into_body().boxed());

    Ok(res)
}

async fn handle_jump(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    get_tracer().in_span("jump", |_cx| {
        bar();
    });
    info!(name = "jump", message = "Jump endpoint hit");

    let res = Response::new(req.into_body().boxed());

    Ok(res)
}

async fn send_request(
    url: &str,
    body_content: &str,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = Client::builder(TokioExecutor::new()).build_http();

    let cx = Context::current();

    let mut req = hyper::Request::builder().uri(url);
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(req.headers_mut().unwrap()))
    });

    let res = client
        .request(req.body(Full::new(Bytes::from(body_content.to_string())))?)
        .await?;

    info!(name: "Jump ResponseReceived", status = res.status().to_string());

    Ok(())
}

async fn router(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
    // Extract the context from the incoming request headers
    let parent_cx = extract_context_from_request(&req);
    let response = {
        // Create a span parenting the remote client span.
        let tracer = get_tracer();
        let span = tracer
            .span_builder("router")
            .with_kind(SpanKind::Server)
            .start_with_context(tracer, &parent_cx);

        info!(name = "router", message = "Dispatching request");

        let cx = parent_cx.with_span(span);
        match (req.method(), req.uri().path()) {
            (&hyper::Method::GET, "/health") => handle_health_check(req).with_context(cx).await,
            (&hyper::Method::GET, "/echo") => handle_echo(req).with_context(cx).await,
            (&hyper::Method::GET, "/jump") => handle_jump(req).with_context(cx).await,
            _ => {
                cx.span()
                    .set_attribute(KeyValue::new(trace::HTTP_RESPONSE_STATUS_CODE, 404));
                let mut not_found = Response::new(BoxBody::default());
                *not_found.status_mut() = StatusCode::NOT_FOUND;
                Ok(not_found)
            }
        }
    };

    response
}

/// A custom log processor that enriches LogRecords with DD propagation data.
#[derive(Debug)]
struct EnrichWithBaggageLogProcessor;
impl LogProcessor for EnrichWithBaggageLogProcessor {
    fn emit(&self, _data: &mut SdkLogRecord, _instrumentation: &InstrumentationScope) {
        Context::map_current(|_cx| {
            // if let Some(propagation_data) = cx.get::<DatadogExtractData>() {
            //     data.add_attribute("dd_propagation_data", propagation_data.to_string());
            // }
        });
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown(&self) -> OTelSdkResult {
        Ok(())
    }
}

/// A custom span processor that enriches spans with baggage attributes. Baggage
/// information is not added automatically without this processor.
#[derive(Debug)]
struct EnrichWithBaggageSpanProcessor;
impl SpanProcessor for EnrichWithBaggageSpanProcessor {
    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: std::time::Duration) -> OTelSdkResult {
        Ok(())
    }

    fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &Context) {
        for (kk, vv) in cx.baggage().iter() {
            span.set_attribute(KeyValue::new(kk.clone(), vv.0.clone()));
        }
    }

    fn on_end(&self, _span: opentelemetry_sdk::trace::SpanData) {}
}

fn init_tracer() -> SdkTracerProvider {
    let config = dd_trace::Config::builder()
        .set_service("rust-propagator-service-example".to_string())
        .set_env("staging".to_string())
        .build();

    datadog_opentelemetry::tracing()
        .with_config(config)
        .with_span_processor(EnrichWithBaggageSpanProcessor)
        .with_span_processor(opentelemetry_sdk::trace::SimpleSpanProcessor::new(
            SpanExporter::default(),
        ))
        .init()
}

fn init_logs() -> SdkLoggerProvider {
    // Setup tracerprovider with stdout exporter
    // that prints the spans to stdout.
    let logger_provider = SdkLoggerProvider::builder()
        .with_log_processor(EnrichWithBaggageLogProcessor)
        .with_simple_exporter(LogExporter::default())
        .build();
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry().with(otel_layer).init();

    logger_provider
}

#[tokio::main]
async fn main() {
    use hyper_util::server::conn::auto::Builder;

    let provider = init_tracer();
    let logger_provider = init_logs();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    while let Ok((stream, _addr)) = listener.accept().await {
        if let Err(err) = Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service_fn(router))
            .await
        {
            eprintln!("{err}");
        }
    }

    provider.shutdown().expect("Shutdown provider failed");
    logger_provider
        .shutdown()
        .expect("Shutdown provider failed");
}

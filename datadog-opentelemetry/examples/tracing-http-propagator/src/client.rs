use dd_trace::configuration::TracePropagationStyle;
use http_body_util::Full;
use hyper::HeaderMap;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use opentelemetry::{
    global,
    trace::{SpanKind, TraceContextExt, Tracer},
    Context,
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_http::{Bytes, HeaderInjector};
use opentelemetry_sdk::{logs::SdkLoggerProvider, trace::SdkTracerProvider};
use opentelemetry_stdout::{LogExporter, SpanExporter};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn init_tracer() -> SdkTracerProvider {
    let mut config = dd_trace::Config::builder();
    config.set_trace_propagation_style(vec![TracePropagationStyle::Datadog]);

    datadog_opentelemetry::init_datadog(
        config.build(),
        SdkTracerProvider::builder().with_simple_exporter(SpanExporter::default()),
    )
}

fn init_logs() -> SdkLoggerProvider {
    // Setup tracerprovider with stdout exporter
    // that prints the spans to stdout.
    let logger_provider = SdkLoggerProvider::builder()
        .with_simple_exporter(LogExporter::default())
        .build();
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    logger_provider
}

async fn send_request(
    url: &str,
    body_content: &str,
    span_name: &str,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let tracer = global::tracer("example/client");
    let span = tracer
        .span_builder(String::from(span_name))
        .with_kind(SpanKind::Client)
        .start(&tracer);
    let cx = Context::current_with_span(span);

    let mut req = hyper::Request::builder().uri(url);
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(req.headers_mut().unwrap()))
    });

    info!(name: "HeadersSent", headers = print_headers(req.headers_mut().unwrap()));

    let res = client
        .request(req.body(Full::new(Bytes::from(body_content.to_string())))?)
        .await?;

    info!(name: "ResponseReceived", status = res.status().to_string(), message = "Response received");

    info!(name: "HeadersReceived", headers = print_headers(res.headers()), message = "Response received");

    Ok(())
}

fn print_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value:?}"))
        .collect::<Vec<String>>()
        .join(",")
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let tracer_provider = init_tracer();
    let logger_provider = init_logs();

    // send_request(
    //     "http://127.0.0.1:3000/health",
    //     "Health Request!",
    //     "server_health_check",
    // )
    // .await?;
    send_request(
        "http://127.0.0.1:3000/echo",
        "Echo Request!",
        "server_echo_check",
    )
    .await?;

    tracer_provider
        .shutdown()
        .expect("Shutdown provider failed");
    logger_provider
        .shutdown()
        .expect("Shutdown provider failed");
    Ok(())
}

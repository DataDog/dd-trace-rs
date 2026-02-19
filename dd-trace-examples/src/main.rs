use axum::{extract::Request, http::Method, response::Json, routing::get, Router};
use datadog_opentelemetry::{self, configuration::Config, log::LevelFilter as DdLevelFilter};
use opentelemetry::trace::TracerProvider;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{field::Empty, info, instrument, level_filters::LevelFilter, Level};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: u32,
    name: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateUserRequest {
    name: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    message: String,
}

#[instrument]
async fn health_check() -> Json<ApiResponse<()>> {
    // Simulate health check
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    info!("Health check performed");

    Json(ApiResponse {
        success: true,
        data: None,
        message: "Service is healthy".to_string(),
    })
}

#[instrument]
async fn root() -> &'static str {
    info!("Root endpoint accessed");
    "Datadog OpenTelemetry Example API\n\nAvailable endpoints:\n- GET /health - Health check\n- GET /users/{id} - Get user by ID\n- POST /users - Create new user"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting Datadog OpenTelemetry example application...");

    // Initialize Datadog OpenTelemetry pipeline
    let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(
            Config::builder()
                .set_trace_agent_url("http://0.0.0.0:8126".into())
                .set_service("dd-trace-example".to_string())
                .set_version("1.0.0".to_string())
                .set_env("development".to_string())
                .set_log_level_filter(DdLevelFilter::Info)
                .build(),
        )
        .init();

    info!("Datadog pipeline initialized successfully");
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(LevelFilter::DEBUG))
        .with(
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("dd-trace-example")),
        )
        .try_init()?;

    // Create CORS layer
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any);

    // Build our application with a route
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .layer(cors)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_span)
                .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                .on_response(DefaultOnResponse::new().level(Level::DEBUG))
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        );

    // Run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    // Shutdown the tracer provider
    tracer_provider.shutdown()?;

    Ok(())
}

fn make_span(request: &Request) -> tracing::Span {
    let route = request.uri().path();
    let span = tracing::info_span!(
        target: "otel::tracing",
        "incoming request",
        // Tracing span name must be a static string, but we can use this field to use a
        // dynamic string for the opentelemetry span name.
        // See https://github.com/tokio-rs/tracing/pull/732.
        otel.name = %route,
        http.grpc_status = Empty,
        http.grpc_status_str = Empty,
        error.message = Empty,
        rpc.system = "grpc",
        uri = %request.uri(),
        route = route,
        org_id = Empty,
        upstream_req_id = Empty,
        query_source = Empty,
    );

    // Extract tracing information from incoming request and propagate it
    // to this span
    let remote_parent_ctx = opentelemetry::global::get_text_map_propagator(|propagator| {
        let extractor = opentelemetry_http::HeaderExtractor(request.headers());
        propagator.extract(&extractor)
    });

    let _ = span.set_parent(remote_parent_ctx.clone());
    span
}

use axum::{
    extract::Path,
    http::{Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use datadog_opentelemetry::DatadogPipeline;
use opentelemetry::{
    global,
    trace::{Span, Tracer},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, instrument, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

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

#[instrument(skip(tracer))]
async fn get_user(Path(id): Path<u32>, tracer: axum::extract::Extension<opentelemetry::global::Tracer>) -> Json<ApiResponse<User>> {
    let span = tracer.start("get_user");
    span.set_attribute(opentelemetry::KeyValue::new("user.id", id.to_string()));
    
    // Simulate some work
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    let user = User {
        id,
        name: format!("User {}", id),
        email: format!("user{}@example.com", id),
    };
    
    info!("Retrieved user: {:?}", user);
    span.end();
    
    Json(ApiResponse {
        success: true,
        data: Some(user),
        message: "User retrieved successfully".to_string(),
    })
}

#[instrument(skip(tracer))]
async fn create_user(
    Json(payload): Json<CreateUserRequest>,
    tracer: axum::extract::Extension<opentelemetry::global::Tracer>,
) -> Json<ApiResponse<User>> {
    let span = tracer.start("create_user");
    span.set_attribute(opentelemetry::KeyValue::new("user.name", payload.name.clone()));
    span.set_attribute(opentelemetry::KeyValue::new("user.email", payload.email.clone()));
    
    // Simulate some work
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    
    let user = User {
        id: rand::random::<u32>() % 10000,
        name: payload.name,
        email: payload.email,
    };
    
    info!("Created user: {:?}", user);
    span.end();
    
    Json(ApiResponse {
        success: true,
        data: Some(user),
        message: "User created successfully".to_string(),
    })
}

#[instrument(skip(tracer))]
async fn health_check(tracer: axum::extract::Extension<opentelemetry::global::Tracer>) -> Json<ApiResponse<()>> {
    let span = tracer.start("health_check");
    
    // Simulate health check
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    
    info!("Health check performed");
    span.end();
    
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
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter("info,datadog_opentelemetry=debug")
        .init();

    info!("Starting Datadog OpenTelemetry example application...");

    // Initialize Datadog OpenTelemetry pipeline
    let pipeline = DatadogPipeline::new()
        .with_service_name("dd-trace-example")
        .with_service_version("1.0.0")
        .with_env("development")
        .with_trace_endpoint("http://localhost:8126/v0.5/traces") // Default Datadog agent endpoint
        .build()?;

    info!("Datadog pipeline initialized successfully");

    // Get the tracer from the pipeline
    let tracer = pipeline.tracer();

    // Set the global tracer
    global::set_tracer_provider(pipeline.trace_provider());

    // Create CORS layer
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any);

    // Build our application with a route
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/users/:id", get(get_user))
        .route("/users", post(create_user))
        .layer(cors)
        .layer(axum::extract::Extension(tracer));

    // Run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on {}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

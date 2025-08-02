# dd-trace-rs Documentation

`dd-trace-rs` is a Rust library for distributed tracing using Datadog. It provides OpenTelemetry-compatible tracing with Datadog-specific features and optimizations.

> ⚠️ **PREVIEW**: This library is currently in preview. Use at your own risk.

## Quick Start

### Basic Usage

```rust
use opentelemetry::trace::Tracer;
use opentelemetry_sdk::trace::SdkTracerProvider;

fn main() {
    // Initialize the Datadog tracer with default configuration
    let tracer_provider = datadog_opentelemetry::init_datadog(
        dd_trace::Config::default(),
        SdkTracerProvider::builder(),
    );

    // Create spans using the global tracer
    opentelemetry::global::tracer("my-app").in_span("my-operation", |_cx| {
        println!("Hello from inside a span!");
    });

    // Shutdown the tracer provider
    tracer_provider.shutdown().expect("Failed to shutdown tracer");
}
```

### Custom Configuration

```rust
use dd_trace::{Config, LogLevel};
use dd_trace::configuration::{SamplingRuleConfig, TracePropagationStyle};
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::collections::HashMap;

fn main() {
    // Build custom configuration
    let mut config_builder = Config::builder();
    
    config_builder
        .set_service("my-rust-service".to_string())
        .set_env("production".to_string())
        .set_version("1.2.3".to_string())
        .set_log_level(LogLevel::Debug)
        .set_trace_agent_url("http://datadog-agent:8126".into())
        .set_trace_rate_limit(1000);

    let config = config_builder.build();

    // Initialize with custom configuration
    let tracer_provider = datadog_opentelemetry::init_datadog(
        config,
        SdkTracerProvider::builder(),
    );

    // Your application code here...
    
    tracer_provider.shutdown().expect("Failed to shutdown tracer");
}
```

## Configuration

### Environment Variables

The library automatically reads configuration from environment variables. Here are the supported variables:

#### Service Identification
- **`DD_SERVICE`**: Service name (default: `"unnamed-rust-service"`)
- **`DD_ENV`**: Environment name (e.g., `production`, `staging`)
- **`DD_VERSION`**: Application version

#### Agent Connection
- **`DD_TRACE_AGENT_URL`**: Datadog trace agent URL (default: `"http://localhost:8126"`)

#### Sampling Configuration
- **`DD_TRACE_SAMPLING_RULES`**: JSON array of sampling rules
- **`DD_TRACE_RATE_LIMIT`**: Maximum spans per second (default: `100`)

#### Global Settings
- **`DD_TAGS`**: Comma-separated list of global tags (e.g., `"key1:value1,key2:value2"`)
- **`DD_TRACE_ENABLED`**: Enable/disable tracing (default: `true`)
- **`DD_LOG_LEVEL`**: Logging level (`DEBUG`, `WARN`, `ERROR`)

#### Trace Propagation
- **`DD_TRACE_PROPAGATION_STYLE`**: Propagation styles to use
- **`DD_TRACE_PROPAGATION_STYLE_EXTRACT`**: Styles for extraction
- **`DD_TRACE_PROPAGATION_STYLE_INJECT`**: Styles for injection
- **`DD_TRACE_PROPAGATION_EXTRACT_FIRST`**: Use first available context (default: `false`)

### Configuration Builder API

#### Basic Settings

```rust
use dd_trace::{Config, LogLevel};

let mut builder = Config::builder();

// Service identification
builder
    .set_service("my-service".to_string())
    .set_env("production".to_string())
    .set_version("1.0.0".to_string());

// Agent configuration
builder.set_trace_agent_url("http://datadog-agent:8126".into());

// Global tags
builder
    .set_global_tags(vec![
        "team:backend".to_string(),
        "component:api".to_string(),
    ])
    .add_global_tag("region:us-east-1".to_string());

// Logging and debugging
builder
    .set_log_level(LogLevel::Debug)
    .set_enabled(true);

let config = builder.build();
```

#### Sampling Configuration

```rust
use dd_trace::configuration::SamplingRuleConfig;
use std::collections::HashMap;

let mut builder = Config::builder();

// Define sampling rules
let sampling_rules = vec![
    SamplingRuleConfig {
        sample_rate: 1.0, // 100% sampling
        service: Some("critical-service".to_string()),
        name: None,
        resource: None,
        tags: HashMap::new(),
        provenance: "custom".to_string(),
    },
    SamplingRuleConfig {
        sample_rate: 0.1, // 10% sampling
        service: Some("background-service".to_string()),
        name: Some("background-job".to_string()),
        resource: None,
        tags: {
            let mut tags = HashMap::new();
            tags.insert("priority".to_string(), "low".to_string());
            tags
        },
        provenance: "custom".to_string(),
    },
];

builder
    .set_trace_sampling_rules(sampling_rules)
    .set_trace_rate_limit(1000); // Max 1000 spans/second

let config = builder.build();
```

#### Trace Propagation

```rust
use dd_trace::configuration::TracePropagationStyle;

let mut builder = Config::builder();

// Configure propagation styles
builder
    .set_trace_propagation_style_extract(vec![
        TracePropagationStyle::Datadog,
        TracePropagationStyle::TraceContext,
    ])
    .set_trace_propagation_style_inject(vec![
        TracePropagationStyle::Datadog,
    ])
    .set_trace_propagation_extract_first(true);

let config = builder.build();
```

### Configuration Types

#### `LogLevel`
- `LogLevel::Debug`: Verbose logging for debugging
- `LogLevel::Warn`: Warning messages only
- `LogLevel::Error`: Error messages only (default)

#### `TracePropagationStyle`
- `TracePropagationStyle::Datadog`: Datadog's native propagation format
- `TracePropagationStyle::TraceContext`: W3C Trace Context standard
- `TracePropagationStyle::None`: Disable propagation

#### `SamplingRuleConfig`
Defines sampling rules for traces:

```rust
pub struct SamplingRuleConfig {
    pub sample_rate: f64,           // 0.0 to 1.0
    pub service: Option<String>,    // Service name pattern
    pub name: Option<String>,       // Span name pattern  
    pub resource: Option<String>,   // Resource name pattern
    pub tags: HashMap<String, String>, // Required tags
    pub provenance: String,         // Rule source
}
```

## Advanced Usage

### HTTP Propagation

For HTTP services, you'll want to extract and inject trace context:

```rust
use opentelemetry::{global, Context};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use hyper::{Request, Response};

// Extract context from incoming request
fn extract_context_from_request(req: &Request<Body>) -> Context {
    global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    })
}

// Inject context into outgoing request
fn inject_context_into_request(req: &mut Request<Body>) {
    let cx = Context::current();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&cx, &mut HeaderInjector(req.headers_mut()))
    });
}
```

### Custom Span Processing

```rust
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanProcessor};

// You can add custom span processors before initialization
let tracer_provider_builder = SdkTracerProvider::builder()
    .with_span_processor(/* your custom processor */);

let tracer_provider = datadog_opentelemetry::init_datadog(
    config,
    tracer_provider_builder,
);
```

### Environment-based Configuration

```bash
# Set environment variables
export DD_SERVICE="my-rust-app"
export DD_ENV="production"
export DD_VERSION="1.2.3"
export DD_TRACE_AGENT_URL="http://datadog-agent:8126"
export DD_TAGS="team:backend,component:api"
export DD_TRACE_SAMPLING_RULES='[{"sample_rate": 0.1, "service": "background-*"}]'
export DD_LOG_LEVEL="DEBUG"
```

```rust
// Configuration will be automatically loaded from environment
let config = Config::default();
```

## Error Handling

The library uses Rust's standard error handling patterns:

```rust
use dd_trace::{Config, Error, Result};

fn setup_tracing() -> Result<()> {
    let config = Config::builder()
        .set_service("my-service".to_string())
        .build();

    let tracer_provider = datadog_opentelemetry::init_datadog(
        config,
        SdkTracerProvider::builder(),
    );

    // Handle shutdown
    match tracer_provider.shutdown() {
        Ok(_) => println!("Tracer shutdown successfully"),
        Err(e) => eprintln!("Failed to shutdown tracer: {}", e),
    }

    Ok(())
}
```

## Best Practices

### 1. Service Identification
Always set service, environment, and version:

```rust
Config::builder()
    .set_service("user-service".to_string())
    .set_env("production".to_string())  
    .set_version("2.1.0".to_string())
    .build()
```

### 2. Sampling Strategy
Configure sampling to balance observability and performance:

```rust
// High-value services: sample everything
SamplingRuleConfig {
    sample_rate: 1.0,
    service: Some("payment-service".to_string()),
    ..Default::default()
}

// Background jobs: sample lightly
SamplingRuleConfig {
    sample_rate: 0.01, // 1%
    service: Some("background-*".to_string()),
    ..Default::default()
}
```

### 3. Global Tags
Use global tags for consistent metadata:

```rust
builder.set_global_tags(vec![
    "datacenter:us-east-1".to_string(),
    "team:platform".to_string(),
    "cost-center:engineering".to_string(),
]);
```

### 4. Rate Limiting
Set appropriate rate limits based on your traffic:

```rust
builder.set_trace_rate_limit(5000); // 5000 spans/second max
```

## Examples

### Web Server with Distributed Tracing

```rust
use hyper::{Body, Request, Response, Server};
use opentelemetry::{global, trace::Tracer, Context};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // Extract parent context
    let parent_cx = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(req.headers()))
    });

    // Create a span in the extracted context
    let tracer = global::tracer("web-server");
    let span = tracer
        .span_builder("handle_request")
        .start_with_context(&tracer, &parent_cx);
    
    let cx = parent_cx.with_span(span);
    let _guard = cx.attach();

    // Your request handling logic here
    Ok(Response::new(Body::from("Hello, World!")))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    let _tracer_provider = datadog_opentelemetry::init_datadog(
        dd_trace::Config::builder()
            .set_service("web-server".to_string())
            .build(),
        opentelemetry_sdk::trace::SdkTracerProvider::builder(),
    );

    // Start server
    let make_svc = hyper::service::make_service_fn(|_conn| async {
        Ok::<_, hyper::Error>(hyper::service::service_fn(handle_request))
    });

    let addr = ([127, 0, 0, 1], 3000).into();
    let server = Server::bind(&addr).serve(make_svc);

    println!("Server running on http://{}", addr);
    server.await.expect("Server error");
}
```

### Background Job with Custom Sampling

```rust
use dd_trace::configuration::SamplingRuleConfig;
use std::collections::HashMap;

fn main() {
    let sampling_rules = vec![
        SamplingRuleConfig {
            sample_rate: 0.1, // 10% sampling for background jobs
            name: Some("process_background_job".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("job_type".to_string(), "background".to_string());
                tags
            },
            ..Default::default()
        },
    ];

    let config = dd_trace::Config::builder()
        .set_service("job-processor".to_string())
        .set_trace_sampling_rules(sampling_rules)
        .build();

    let tracer_provider = datadog_opentelemetry::init_datadog(
        config,
        opentelemetry_sdk::trace::SdkTracerProvider::builder(),
    );

    // Process jobs with tracing
    let tracer = opentelemetry::global::tracer("job-processor");
    tracer.in_span("process_background_job", |cx| {
        cx.span().set_attribute(
            opentelemetry::KeyValue::new("job_type", "background")
        );
        
        // Your job processing logic here
        println!("Processing background job...");
    });

    tracer_provider.shutdown().expect("Failed to shutdown tracer");
}
```

## Troubleshooting

### Common Issues

1. **Traces not appearing in Datadog**
   - Check `DD_TRACE_AGENT_URL` is correct
   - Verify the Datadog agent is running and accessible
   - Enable debug logging: `DD_LOG_LEVEL=DEBUG`

2. **High memory usage**
   - Reduce sampling rate with `DD_TRACE_RATE_LIMIT`
   - Configure sampling rules for high-volume services

3. **Missing trace context**
   - Ensure propagation styles are configured correctly
   - Check that headers are being extracted/injected properly

### Debug Logging

```rust
use dd_trace::LogLevel;

let config = dd_trace::Config::builder()
    .set_log_level(LogLevel::Debug)
    .build();
```

Or via environment variable:
```bash
export DD_LOG_LEVEL=DEBUG
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details. 
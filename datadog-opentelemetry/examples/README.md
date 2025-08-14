# Examples

This directory contains example applications demonstrating various features of the `datadog-opentelemetry` crate.

## Available Examples

### simple_tracing
A basic example showing how to initialize the Datadog tracer and create spans.

**Run:**
```bash
cargo run -p simple_tracing
```

### propagator
An example demonstrating trace propagation between services.

**Run:**
```bash
cargo run -p propagator
```

### remote_config_test
A test application for manually testing the remote configuration feature for sampling rules. This application continuously emits spans under a specific service name (`dd-trace-rs-rc-test-service`) to test remote configuration updates from the Datadog backend.

**Features:**
- Initializes tracer with remote configuration enabled
- Emits ~2 traces per second with realistic span structures
- Creates different operation types: `user_login`, `data_fetch`, `file_upload`, `analytics_event`
- Each trace has a parent span with 2 child spans (`database_query` and `external_api_call`)

**Run:**
```bash
# From project root
cargo run -p remote_config_test

# Or use the convenience script
./run_remote_config_test.sh

# With debug logging to see remote config activity
DD_LOG_LEVEL=DEBUG cargo run -p remote_config_test
```

**Prerequisites:**
- Datadog Agent running on `localhost:8126`
- Agent must have remote configuration enabled
- Agent should be configured to receive remote config from Datadog backend

**Testing Remote Configuration:**
1. Start the application
2. Verify spans are being sent to your APM dashboard
3. Create a sampling rule in your Datadog backend for service `dd-trace-rs-rc-test-service`
4. Monitor the application and APM dashboard to see sampling rate changes

See the [remote_config_test README](remote_config_test/README.md) for detailed instructions.

# Remote Configuration Test Application

This is a test application for manually testing the remote configuration feature for sampling rules in `dd-trace-rs`. It continuously emits spans under a specific service name so you can test remote configuration updates from the Datadog backend.

## What it does

- Initializes the Datadog tracer with remote configuration enabled
- Continuously emits spans under the service name `dd-trace-rs-rc-test-service`
- Creates realistic traces with multiple spans (parent + 2 child spans)
- Simulates different operation types: `user_login`, `data_fetch`, `file_upload`, `analytics_event`
- Emits approximately 2 traces per second
- Logs progress every 10 traces

## Prerequisites

1. **Datadog Agent**: You need a Datadog Agent running on `localhost:8126` that is configured to receive remote configuration updates from the Datadog backend.

2. **Agent Configuration**: Your agent should have remote configuration enabled. Check your agent's configuration for:
   ```yaml
   remote_configuration:
     enabled: true
   ```

## How to run

### Option 1: From the project root
```bash
# Build and run the test application
cargo run --bin remote_config_test -p remote_config_test
```

### Option 2: From the example directory
```bash
cd datadog-opentelemetry/examples/remote_config_test
cargo run
```

## Environment Variables

You can customize the behavior using these environment variables:

- `DD_TRACE_AGENT_URL`: Agent URL (default: `http://localhost:8126`)
- `DD_LOG_LEVEL`: Log level for Datadog tracing (default: `INFO`)
- `DD_REMOTE_CONFIGURATION_ENABLED`: Enable/disable remote config (default: `true`)

Example with custom agent URL:
```bash
DD_TRACE_AGENT_URL=http://localhost:8126 cargo run
```

## Testing Remote Configuration

1. **Start the application**: Run the test application using one of the methods above.

2. **Verify spans are being sent**: Check your Datadog APM dashboard to confirm spans from `dd-trace-rs-rc-test-service` are being received.

3. **Create a sampling rule**: In your Datadog backend, create a sampling rule for the service:
   - Service: `dd-trace-rs-rc-test-service`
   - Sample rate: Choose a rate (e.g., 0.1 for 10% sampling)

4. **Monitor for changes**: Watch the application logs and your APM dashboard to see if the sampling rate changes when the remote configuration is applied.

## Expected Behavior

- **Initial**: The application should emit spans at whatever the default sampling rate is
- **After remote config update**: The sampling rate should change according to your remote configuration rule
- **Remote config polling**: The client polls for configuration updates every 5 seconds (as per the spec)

## Debugging

### Increase logging verbosity
```bash
DD_LOG_LEVEL=DEBUG cargo run
```

### Check agent connectivity
Make sure your agent is accessible:
```bash
curl http://localhost:8126/v0.7/config
```

### Check spans are reaching the agent
```bash
curl http://localhost:8126/info
```

## What to look for

When remote configuration is working correctly, you should see:

1. **In application logs**: Periodic remote config client activity
2. **In agent logs**: Remote configuration requests and responses
3. **In APM dashboard**: Changes in sampling rate for the `dd-trace-rs-rc-test-service`

## Stopping the application

Press `Ctrl+C` to gracefully stop the application. It will flush any remaining spans before shutting down. 
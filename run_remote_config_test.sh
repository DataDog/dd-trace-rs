#!/bin/bash

# Remote Configuration Test Script
# This script runs the remote configuration test application

echo "🔧 Remote Configuration Test for dd-trace-rs"
echo "============================================="
echo

# Check if agent is reachable
echo "🌐 Checking agent connectivity..."
if curl -s "http://localhost:8126/info" > /dev/null 2>&1; then
    echo "✅ Agent at localhost:8126 is reachable"
else
    echo "❌ Agent at localhost:8126 is not reachable"
    echo "   Make sure your Datadog Agent is running with remote config enabled"
    echo
fi

# Set up defaults if not set
export DD_TRACE_AGENT_URL="${DD_TRACE_AGENT_URL:-http://localhost:8126}"
export DD_LOG_LEVEL="${DD_LOG_LEVEL:-INFO}"
export DD_REMOTE_CONFIGURATION_ENABLED="${DD_REMOTE_CONFIGURATION_ENABLED:-true}"

# Show current environment
echo "📋 Environment variables:"
echo "   DD_TRACE_AGENT_URL: ${DD_TRACE_AGENT_URL}"
echo "   DD_LOG_LEVEL: ${DD_LOG_LEVEL}"
echo "   DD_REMOTE_CONFIGURATION_ENABLED: ${DD_REMOTE_CONFIGURATION_ENABLED}"
echo

echo "🚀 Starting remote config test application..."
echo "   Service name: dd-trace-rs-rc-test-service"
echo "   The app will emit ~2 traces per second"
echo "   Press Ctrl+C to stop"
echo

# Run the application
exec cargo run -p remote_config_test

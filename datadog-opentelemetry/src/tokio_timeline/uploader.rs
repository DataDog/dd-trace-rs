// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! HTTP uploader for timeline data to Datadog profiling endpoint.

use std::sync::Arc;
use std::time::SystemTime;

use crate::core::configuration::Config;
use crate::tokio_timeline::serializer::SerializedTimeline;

/// Error type for upload failures.
#[derive(Debug)]
pub enum UploadError {
    /// Failed to build HTTP request.
    RequestBuild(String),
    /// HTTP request failed.
    Http(String),
    /// Server returned non-success status.
    Server { status: u16, body: String },
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::RequestBuild(msg) => write!(f, "request build error: {}", msg),
            UploadError::Http(msg) => write!(f, "HTTP error: {}", msg),
            UploadError::Server { status, body } => {
                write!(f, "server error ({}): {}", status, body)
            }
        }
    }
}

impl std::error::Error for UploadError {}

/// Uploader for sending timeline data to Datadog.
pub struct TimelineUploader {
    /// Datadog configuration.
    config: Arc<Config>,
    /// Multipart boundary string.
    boundary: String,
}

impl TimelineUploader {
    /// Creates a new timeline uploader.
    pub fn new(config: Arc<Config>) -> Self {
        let boundary = format!("----TimelineBoundary{}", uuid::Uuid::new_v4());
        Self { config, boundary }
    }

    /// Builds the profiling endpoint URL.
    fn profiling_url(&self) -> String {
        let base_url = self.config.trace_agent_url();
        // Remove /v0.x/traces suffix if present and add profiling endpoint
        let base = base_url
            .trim_end_matches('/')
            .trim_end_matches("/v0.4/traces")
            .trim_end_matches("/v0.5/traces")
            .trim_end_matches("/v0.7/traces");
        format!("{}/profiling/v1/input", base)
    }

    /// Builds the event JSON for the profiling upload.
    fn build_event_json(
        &self,
        batch_start: SystemTime,
        batch_end: SystemTime,
        attachments: &[&str],
    ) -> String {
        let start_iso = systemtime_to_iso8601(batch_start);
        let end_iso = systemtime_to_iso8601(batch_end);

        let attachments_json: Vec<String> =
            attachments.iter().map(|a| format!("\"{}\"", a)).collect();

        // Use "go" family for timeline visualization with Go trace format
        let (family, language, runtime) = ("go", "go", "go1.22.0");

        // Build tags string - service is required first
        let mut tags = Vec::new();
        let service: &str = &self.config.service();
        tags.push(format!("service:{service}"));

        // Add optional tags
        if let Some(env) = self.config.env() {
            let env: &str = env;
            tags.push(format!("env:{env}"));
        }
        if let Some(version) = self.config.version() {
            let version: &str = version;
            tags.push(format!("version:{version}"));
        }

        // Add host tag - important for profiling
        if let Ok(hostname) = std::env::var("DD_HOSTNAME").or_else(|_| {
            gethostname::gethostname()
                .into_string()
                .map_err(|_| std::env::VarError::NotPresent)
        }) {
            tags.push(format!("host:{hostname}"));
        }

        tags.push(format!("runtime-id:{}", self.config.runtime_id()));
        tags.push(format!("process_id:{}", std::process::id()));
        tags.push(format!("language:{language}"));
        tags.push(format!("runtime:{runtime}"));
        tags.push(format!("runtime_version:{runtime}"));
        tags.push(format!("runtime_arch:{}", std::env::consts::ARCH));
        tags.push(format!("runtime_os:{}", std::env::consts::OS));
        tags.push("profiler_version:1.67.0".to_string());
        tags.push("profile_seq:0".to_string());

        // Add go_execution_traced tag for timeline visualization
        tags.push("go_execution_traced:yes".to_string());

        // Build the event JSON with all required fields
        // The "info" field is required by Datadog's profiling backend
        format!(
            r#"{{"version":"4","family":"{}","start":"{}","end":"{}","tags_profiler":"{}","attachments":[{}],"info":{{"profiler":{{"activation":"manual","ssi":{{}},"settings":{{}}}}}}}}"#,
            family,
            start_iso,
            end_iso,
            tags.join(","),
            attachments_json.join(",")
        )
    }

    /// Builds a multipart form body.
    fn build_multipart_body(&self, event_json: &str, timelines: &[&SerializedTimeline]) -> Vec<u8> {
        let mut body = Vec::new();

        // Event part
        body.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"event\"; filename=\"event.json\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
        body.extend_from_slice(event_json.as_bytes());
        body.extend_from_slice(b"\r\n");

        // Timeline data parts
        // Note: Datadog expects the form field name to match the filename (e.g., "go.trace" for
        // both)
        for timeline in timelines {
            body.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                    timeline.filename, timeline.filename
                )
                .as_bytes(),
            );
            body.extend_from_slice(
                format!("Content-Type: {}\r\n\r\n", timeline.content_type).as_bytes(),
            );
            body.extend_from_slice(&timeline.data);
            body.extend_from_slice(b"\r\n");
        }

        // Final boundary
        body.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());

        body
    }

    /// Uploads timeline data to Datadog.
    ///
    /// This is a blocking operation that should be called from a background thread.
    pub fn upload(
        &self,
        timelines: &[SerializedTimeline],
        batch_start: SystemTime,
        batch_end: SystemTime,
    ) -> Result<(), UploadError> {
        if timelines.is_empty() {
            return Ok(());
        }

        let attachments: Vec<&str> = timelines.iter().map(|t| t.filename).collect();
        let event_json = self.build_event_json(batch_start, batch_end, &attachments);

        let timeline_refs: Vec<&SerializedTimeline> = timelines.iter().collect();
        let body = self.build_multipart_body(&event_json, &timeline_refs);

        let url = self.profiling_url();
        let content_type = format!("multipart/form-data; boundary={}", self.boundary);

        // Use blocking HTTP client
        self.send_blocking(&url, &content_type, body)
    }

    /// Sends the request using a blocking HTTP client.
    fn send_blocking(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<(), UploadError> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Parse URL
        let url_parsed = url
            .strip_prefix("http://")
            .ok_or_else(|| UploadError::RequestBuild("only http:// URLs supported".into()))?;

        let (host_port, path) = url_parsed
            .split_once('/')
            .map(|(h, p)| (h, format!("/{}", p)))
            .unwrap_or((url_parsed, "/profiling/v1/input".to_string()));

        let host = host_port.split(':').next().unwrap_or(host_port);

        // Build HTTP request
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            path,
            host,
            content_type,
            body.len()
        );

        // Connect and send
        let mut stream = TcpStream::connect(host_port)
            .map_err(|e| UploadError::Http(format!("connection failed: {}", e)))?;

        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();

        stream
            .write_all(request.as_bytes())
            .map_err(|e| UploadError::Http(format!("write failed: {}", e)))?;
        stream
            .write_all(&body)
            .map_err(|e| UploadError::Http(format!("write body failed: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| UploadError::Http(format!("read failed: {}", e)))?;

        // Parse status code from response
        let response_str = String::from_utf8_lossy(&response);
        let status = parse_http_status(&response_str);

        if !(200..300).contains(&status) {
            return Err(UploadError::Server {
                status,
                body: response_str.to_string(),
            });
        }

        Ok(())
    }
}

/// Converts a SystemTime to ISO 8601 format string (RFC 3339).
fn systemtime_to_iso8601(time: SystemTime) -> String {
    jiff::Timestamp::try_from(time)
        .map(|ts| ts.to_string())
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Parses HTTP status code from response.
fn parse_http_status(response: &str) -> u16 {
    // HTTP/1.1 200 OK
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemtime_to_iso8601() {
        let time = SystemTime::UNIX_EPOCH;
        let iso = systemtime_to_iso8601(time);
        assert!(iso.starts_with("1970-01-01T00:00:00"));

        // Test a known time (1 day after epoch)
        let one_day = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86400);
        let iso = systemtime_to_iso8601(one_day);
        assert!(iso.starts_with("1970-01-02T00:00:00"));
    }

    #[test]
    fn test_parse_http_status() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_http_status("HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(
            parse_http_status("HTTP/1.1 500 Internal Server Error\r\n"),
            500
        );
        assert_eq!(parse_http_status("invalid"), 0);
    }

    #[test]
    fn test_build_event_json() {
        let config = Arc::new(
            Config::builder()
                .set_service("test-service".to_string())
                .set_env("test".to_string())
                .build(),
        );
        let uploader = TimelineUploader::new(config);

        let json = uploader.build_event_json(
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
            &["go.trace"],
        );

        assert!(json.contains("\"version\":\"4\""));
        assert!(json.contains("\"family\":\"go\"")); // go.trace uses go family for timeline visualization
        assert!(json.contains("service:test-service"));
        assert!(json.contains("env:test"));
        assert!(json.contains("\"go.trace\""));
        assert!(json.contains("go_execution_traced:yes"));
    }

    #[test]
    fn test_build_multipart_body() {
        let config = Arc::new(Config::builder().build());
        let uploader = TimelineUploader::new(config);

        let timeline = SerializedTimeline {
            data: vec![1, 2, 3, 4],
            name: "execution-trace",
            filename: "test.trace",
            content_type: "application/octet-stream",
        };

        let body = uploader.build_multipart_body("{}", &[&timeline]);

        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("Content-Disposition: form-data"));
        assert!(body_str.contains("name=\"event\""));
        assert!(body_str.contains("name=\"test.trace\""));
    }

    #[test]
    fn test_profiling_url() {
        let config = Arc::new(
            Config::builder()
                .set_trace_agent_url("http://localhost:8126/v0.4/traces".to_string())
                .build(),
        );
        let uploader = TimelineUploader::new(config);

        assert_eq!(
            uploader.profiling_url(),
            "http://localhost:8126/profiling/v1/input"
        );
    }
}

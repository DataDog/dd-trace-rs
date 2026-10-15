// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::{Config, HttpErrorStatuses};

pub(crate) const VERSION_KEY: &str = "version";

#[derive(Debug, Clone)]
pub(crate) struct CachedConfig {
    pub tracer_version: String,
    pub service: String,
    pub global_tags: Vec<(String, String)>,
    pub version: Option<String>,
    pub http_server_error_statuses: HttpErrorStatuses,
    pub http_client_error_statuses: HttpErrorStatuses,
}

impl CachedConfig {
    pub fn new(cfg: &Config) -> Self {
        let service = cfg.service().to_string();

        let global_tags = cfg
            .global_tags()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();

        let version = cfg.version().map(String::from);

        Self {
            tracer_version: cfg.tracer_version().to_string(),
            service,
            global_tags,
            version,
            http_server_error_statuses: cfg.trace_http_server_error_statuses().clone(),
            http_client_error_statuses: cfg.trace_http_client_error_statuses().clone(),
        }
    }
}

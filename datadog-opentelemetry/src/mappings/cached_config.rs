// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::core::configuration::Config;

pub(crate) const VERSION_KEY: &str = "version";

#[derive(Debug, Clone)]
pub(crate) struct CachedConfig {
    service: String,
    global_tags: Vec<(String, String)>,
    version: Option<String>,
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
            service,
            global_tags,
            version,
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn global_tags(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.global_tags
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

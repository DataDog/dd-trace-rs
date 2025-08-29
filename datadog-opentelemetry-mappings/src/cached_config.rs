// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use tinybytes::BytesString;

pub const VERSION_KEY: BytesString = BytesString::from_static("version");

#[derive(Debug, Clone)]
pub struct CachedConfig {
    service: BytesString,
    global_tags: Vec<(BytesString, BytesString)>,
    version: Option<BytesString>,
}

impl CachedConfig {
    pub fn new(cfg: &dd_trace::Config) -> Self {
        let service = BytesString::from_string(cfg.service().to_string());

        let global_tags = cfg
            .global_tags()
            .map(|(key, value)| {
                (
                    BytesString::from_string(key.to_string()),
                    BytesString::from_string(value.to_string()),
                )
            })
            .collect();

        let version = cfg
            .version()
            .map(|v| BytesString::from_string(v.to_string()));

        Self {
            service,
            global_tags,
            version,
        }
    }

    pub fn service(&self) -> BytesString {
        self.service.clone()
    }

    pub fn global_tags(&self) -> impl Iterator<Item = (BytesString, BytesString)> + '_ {
        self.global_tags.iter().map(|(k, v)| (k.clone(), v.clone()))
    }

    pub fn version(&self) -> Option<BytesString> {
        self.version.clone()
    }
}

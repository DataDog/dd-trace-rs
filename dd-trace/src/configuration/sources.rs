// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, fmt::Display, str::FromStr};

use ddtelemetry::data::ConfigurationOrigin;

use crate::configuration::supported_configurations::{
    SupportedConfigurations,
};

/// Source of a configuration value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSourceOrigin {
    Default,
    EnvVar,
    Code,
    RemoteConfig,
}

impl From<ConfigSourceOrigin> for ConfigurationOrigin {
    fn from(val: ConfigSourceOrigin) -> Self {
        match val {
            ConfigSourceOrigin::Default => ConfigurationOrigin::Default,
            ConfigSourceOrigin::Code => ConfigurationOrigin::Code,
            ConfigSourceOrigin::EnvVar => ConfigurationOrigin::EnvVar,
            ConfigSourceOrigin::RemoteConfig => ConfigurationOrigin::RemoteConfig,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct ConfigKey<T> {
    pub(crate) value: T,
    pub(crate) origin: ConfigSourceOrigin,
}

/// Compose multiple sources of configuration together.
///
/// The higher precedence sources are the first ones in the list.
pub(crate) struct CompositeSource {
    sources: Vec<Box<dyn ConfigurationSource>>,
}

impl CompositeSource {
    pub fn add_source<C: ConfigurationSource + 'static>(&mut self, source: C) {
        self.sources.push(Box::new(source));
    }

    pub fn new() -> Self {
        CompositeSource {
            sources: Vec::new(),
        }
    }

    pub fn default_sources() -> Self {
        let mut sources = Self::new();
        sources.add_source(EnvSource);
        sources
    }
}

#[allow(unused)]
#[derive(Debug, PartialEq)]
pub(crate) struct CompositeParseError {
    desired_type: &'static str,
    error: Cow<'static, str>,
    value: String,
    origin: ConfigSourceOrigin,
}

#[derive(Debug, PartialEq)]
pub(crate) struct CompositeConfigSourceResult<T> {
    pub name: SupportedConfigurations,
    pub value: Option<ConfigKey<T>>,
    #[allow(unused)]
    // TODO: log errors in debug mode, and send them through telemetry
    pub errors: Vec<CompositeParseError>,
}

impl CompositeSource {
    pub fn get(&self, key: SupportedConfigurations) -> CompositeConfigSourceResult<String> {
        self.get_parse(key)
    }

    /// Get a value from the configuration sources
    ///
    /// This method will iterate over sources in order of precedence
    /// and return the first valid value found. If no value is found, it will return None.
    ///
    /// It will return all parsing errors encountered before finding a valid value, and associate
    /// them with the source they came from.
    pub fn get_parse<T: FromStr<Err = impl Display>>(
        &self,
        name: SupportedConfigurations,
    ) -> CompositeConfigSourceResult<T> {
        let mut errors = Vec::new();
        for s in &self.sources {
            match s.get(name.as_str()).and_then(|value| {
                value
                    .parse::<T>()
                    .map_err(|e| ConfigSourceError::FailedParsing {
                        desired_type: std::any::type_name::<T>(),
                        error: Cow::Owned(e.to_string()),
                        value,
                    })
            }) {
                Ok(v) => {
                    return CompositeConfigSourceResult {
                        name,
                        value: Some(ConfigKey {
                            value: v,
                            origin: s.origin(),
                        }),
                        errors,
                    };
                }
                Err(ConfigSourceError::Missing) => continue,
                Err(ConfigSourceError::FailedParsing {
                    error,
                    value,
                    desired_type,
                }) => {
                    errors.push(CompositeParseError {
                        desired_type,
                        error,
                        value,
                        origin: s.origin(),
                    });
                }
            }
        }
        CompositeConfigSourceResult {
            name,
            value: None,
            errors,
        }
    }
}

pub(crate) enum ConfigSourceError {
    Missing,
    FailedParsing {
        desired_type: &'static str,
        error: Cow<'static, str>,
        // String representation of the value we failed to parse
        value: String,
    },
}

type ConfigSourceResult<T> = Result<T, ConfigSourceError>;

/// Represent a source of configuration
///
/// Configuration
pub(crate) trait ConfigurationSource {
    fn origin(&self) -> ConfigSourceOrigin;

    fn get(&self, key: &'static str) -> ConfigSourceResult<String>;
}

pub(crate) struct EnvSource;

impl ConfigurationSource for EnvSource {
    fn origin(&self) -> ConfigSourceOrigin {
        ConfigSourceOrigin::EnvVar
    }

    fn get(&self, key: &'static str) -> ConfigSourceResult<String> {
        #[allow(clippy::disallowed_methods)]
        std::env::var(key).map_err(|_| ConfigSourceError::Missing)
    }
}

#[allow(unused)]
/// A source of configuration that is backed by a HashMap
/// This is used only for testing purposes
pub(crate) struct HashMapSource {
    map: std::collections::HashMap<String, String>,
    origin: ConfigSourceOrigin,
}

impl HashMapSource {
    #[allow(unused)]
    /// This is used only for testing purposes
    pub(crate) fn from_iter<U: ToString, V: ToString, T: IntoIterator<Item = (U, V)>>(
        map: T,
        origin: ConfigSourceOrigin,
    ) -> Self {
        HashMapSource {
            map: map
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            origin,
        }
    }
}

impl ConfigurationSource for HashMapSource {
    fn origin(&self) -> ConfigSourceOrigin {
        self.origin
    }

    fn get(&self, key: &'static str) -> ConfigSourceResult<String> {
        self.map.get(key).cloned().ok_or(ConfigSourceError::Missing)
    }
}

#[cfg(test)]
mod tests {

    use crate::configuration::sources::ConfigKey;
    use crate::configuration::supported_configurations::SupportedConfigurations;
    use super::{
        CompositeConfigSourceResult, CompositeParseError, CompositeSource, ConfigSourceOrigin,
        HashMapSource,
    };

    #[test]
    fn test_composite_source_single_origin() {
        let mut source = CompositeSource::new();
        source.add_source(HashMapSource::from_iter(
            [("DD_SERVICE", "test-service"), ("DD_ENV", "test-env")],
            ConfigSourceOrigin::EnvVar,
        ));

        for (key, expected) in [
            (
                SupportedConfigurations::DD_SERVICE,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_SERVICE,
                    value: Some(super::ConfigKey {
                        value: "test-service".to_string(),
                        origin: ConfigSourceOrigin::EnvVar,
                    }),
                    errors: vec![],
                },
            ),
            (
                SupportedConfigurations::DD_ENV,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_ENV,
                    value: Some(super::ConfigKey {
                        value: "test-env".to_string(),
                        origin: ConfigSourceOrigin::EnvVar,
                    }),
                    errors: vec![],
                },
            ),
            (
                SupportedConfigurations::DD_VERSION,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_VERSION,
                    value: None,
                    errors: vec![],
                },
            ),
        ] {
            let result = source.get(key);
            assert_eq!(result, expected, "Failed for key: {:?}", key.as_str());
        }
    }

    #[test]
    fn test_composite_priority_order() {
        let mut source = CompositeSource::new();
        source.add_source(HashMapSource::from_iter(
            [("DD_SERVICE", "test-service-env_var")],
            ConfigSourceOrigin::EnvVar,
        ));
        source.add_source(HashMapSource::from_iter(
            [
                ("DD_SERVICE", "test-service-default"),
                ("DD_ENV", "test-env-default"),
            ],
            ConfigSourceOrigin::Default,
        ));

        for (key, expected) in [
            (
                SupportedConfigurations::DD_SERVICE,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_SERVICE,
                    value: Some(super::ConfigKey {
                        value: "test-service-env_var".to_string(),
                        origin: ConfigSourceOrigin::EnvVar,
                    }),
                    errors: vec![],
                },
            ),
            (
                SupportedConfigurations::DD_ENV,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_ENV,
                    value: Some(super::ConfigKey {
                        value: "test-env-default".to_string(),
                        origin: ConfigSourceOrigin::Default,
                    }),
                    errors: vec![],
                },
            ),
            (
                SupportedConfigurations::DD_VERSION,
                CompositeConfigSourceResult {
                    name: SupportedConfigurations::DD_VERSION,
                    value: None,
                    errors: vec![],
                },
            ),
        ] {
            let result = source.get(key);
            assert_eq!(result, expected, "Failed for key: {:?}", key.as_str());
        }
    }

    #[test]
    fn test_composite_parse_error_collection() {
        let mut source = CompositeSource::new();
        source.add_source(HashMapSource::from_iter(
            [("DD_TRACE_ENABLED", "foo")],
            ConfigSourceOrigin::Code,
        ));
        source.add_source(HashMapSource::from_iter(
            [("DD_TRACE_ENABLED", "true")],
            ConfigSourceOrigin::EnvVar,
        ));
        source.add_source(HashMapSource::from_iter(
            [("DD_TRACE_ENABLED", "bar")],
            ConfigSourceOrigin::Default,
        ));

        let result: CompositeConfigSourceResult<bool> = source.get_parse(SupportedConfigurations::DD_TRACE_ENABLED);
        assert_eq!(
            result,
            CompositeConfigSourceResult {
                name: SupportedConfigurations::DD_TRACE_ENABLED,
                value: Some(ConfigKey {
                    value: true,
                    origin: ConfigSourceOrigin::EnvVar,
                }),
                errors: vec![CompositeParseError {
                    desired_type: "bool",
                    error: "provided string was not `true` or `false`".into(),
                    value: "foo".to_string(),
                    origin: ConfigSourceOrigin::Code,
                },],
            }
        )
    }

    #[test]
    fn test_parse_complex_config() {
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct ComplexStruct {
            key: String,
        }
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct ComplexConfig(Vec<ComplexStruct>);

        let mut source = CompositeSource::new();
        source.add_source(HashMapSource::from_iter(
            [(
                "DD_COMPLEX_STRUCT",
                "[
                {\"key\": \"value\"},
                {\"key\": \"value2\"}
            ]",
            )],
            ConfigSourceOrigin::Code,
        ));

        impl std::str::FromStr for ComplexConfig {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                serde_json::from_str(s).map_err(|e| e.to_string())
            }
        }

        let result = source.get_parse(SupportedConfigurations::DD_COMPLEX_STRUCT);
        assert_eq!(
            result,
            CompositeConfigSourceResult {
                name: SupportedConfigurations::DD_COMPLEX_STRUCT,
                value: Some(ConfigKey {
                    value: ComplexConfig(vec![
                        ComplexStruct {
                            key: "value".to_string()
                        },
                        ComplexStruct {
                            key: "value2".to_string()
                        }
                    ]),
                    origin: ConfigSourceOrigin::Code,
                }),
                errors: vec![],
            }
        );
    }
}

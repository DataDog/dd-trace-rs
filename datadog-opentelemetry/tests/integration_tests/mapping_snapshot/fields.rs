// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Dedicated fields, service/type inference and env/version source precedence.

use datadog_opentelemetry::configuration::ConfigBuilder;
use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{SpanBuilder, SpanKind, TracerProvider},
    InstrumentationScope, KeyValue,
};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};

use super::{emit, ignored_name_span, resource, start_span, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Dedicated Datadog fields and conventional overrides
    MappingCase {
        name: "dd_fields__all_overrides",
        configure: None,
        resource: None,
        run: dd_fields_all_overrides,
    },
    MappingCase {
        name: "dd_fields__span_kind_attribute",
        configure: None,
        resource: None,
        run: dd_fields_span_kind_attribute,
    },
    MappingCase {
        name: "dd_fields__span_kind_attribute_case_sensitive",
        configure: None,
        resource: None,
        run: dd_fields_span_kind_attribute_case_sensitive,
    },
    MappingCase {
        name: "attributes__dd_convention_fields",
        configure: None,
        resource: None,
        run: attributes_dd_convention_fields,
    },
    MappingCase {
        name: "dd_fields__dedicated_beats_conventional_and_resource",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("service.name", "resource-service"),
                KeyValue::new("resource.name", "resource-resource"),
                KeyValue::new("span.type", "resource-type"),
            ])
        }),
        run: |p, _| {
            emit(
                p,
                "conflict",
                SpanKind::Client,
                vec![
                    KeyValue::new("datadog.service", "dd-service"),
                    KeyValue::new("service.name", "span-service"),
                    KeyValue::new("datadog.name", "dd-name"),
                    KeyValue::new("operation.name", "span-name"),
                    KeyValue::new("datadog.resource", "dd-resource"),
                    KeyValue::new("resource.name", "span-resource"),
                    KeyValue::new("datadog.type", "dd-type"),
                    KeyValue::new("span.type", "span-type"),
                ],
            )
        },
    },
    MappingCase {
        name: "dd_fields__empty_dedicated_fallbacks",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("service.name", "resource-service"),
                KeyValue::new("resource.name", "resource-resource"),
                KeyValue::new("span.type", "resource-type"),
            ])
        }),
        run: |p, _| {
            emit(
                p,
                "empty-overrides",
                SpanKind::Client,
                vec![
                    KeyValue::new("datadog.service", ""),
                    KeyValue::new("service.name", ""),
                    KeyValue::new("datadog.name", ""),
                    KeyValue::new("datadog.resource", ""),
                    KeyValue::new("resource.name", "span-resource"),
                    KeyValue::new("datadog.type", ""),
                    KeyValue::new("span.type", "span-type"),
                ],
            )
        },
    },
    // Environment and version promotion
    MappingCase {
        name: "env_version__dd_env_attribute",
        configure: None,
        resource: None,
        run: env_version_dd_env_attribute,
    },
    MappingCase {
        name: "env_version__deployment_environment_resource",
        configure: None,
        resource: Some(env_version_deployment_environment_resource_res),
        run: ignored_name_span,
    },
    MappingCase {
        name: "env_version__deployment_environment_name_resource",
        configure: None,
        resource: Some(env_version_deployment_environment_name_resource_res),
        run: ignored_name_span,
    },
    MappingCase {
        name: "env_version__dd_env_beats_resource",
        configure: None,
        resource: Some(env_version_dd_env_beats_resource_res),
        run: env_version_dd_env_beats_resource,
    },
    // `service.version` on the resource sets the span version.
    MappingCase {
        name: "env_version__service_version_resource",
        configure: None,
        resource: Some(env_version_service_version_resource_res),
        run: ignored_name_span,
    },
    // The configured version is applied as the `version` tag when the span service is
    // the resource's `service.name`.
    MappingCase {
        name: "env_version__config_version",
        configure: Some(env_version_config_version_config),
        resource: Some(env_version_config_version_res),
        run: ignored_name_span,
    },
    MappingCase {
        name: "attributes__promoted_meta_keys",
        configure: None,
        resource: None,
        run: attributes_promoted_meta_keys,
    },
    // The configured env is applied to the resource, which resolves the span env.
    MappingCase {
        name: "config__env",
        configure: Some(config_env_config),
        resource: None,
        run: ignored_name_span,
    },
    MappingCase {
        name: "env_version__scope_span_config_conflicts",
        configure: Some(|cfg| {
            cfg.set_version("config-version".into())
                .set_env("config-env".into());
        }),
        resource: Some(|| {
            resource(vec![
                KeyValue::new("service.name", "app"),
                KeyValue::new("env", "resource-env"),
                KeyValue::new("version", "resource-version"),
                KeyValue::new("deployment.environment.name", "deployment-env"),
                KeyValue::new("service.version", "service-version"),
            ])
        }),
        run: promotion_conflicts,
    },
    MappingCase {
        name: "env_version__absent_resource_promoted_tags",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("deployment.environment", "old-env"),
                KeyValue::new("deployment.environment.name", "new-env"),
                KeyValue::new("service.version", "resource-version"),
            ])
        }),
        run: empty_promoted_tags,
    },
    MappingCase {
        name: "env_version__empty_resource_promoted_tags",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("env", ""),
                KeyValue::new("version", ""),
                KeyValue::new("deployment.environment", "old-env"),
                KeyValue::new("deployment.environment.name", "new-env"),
                KeyValue::new("service.version", "resource-version"),
            ])
        }),
        run: empty_promoted_tags,
    },
    // Service resolution
    MappingCase {
        name: "attributes__service_name_span_attribute",
        configure: None,
        resource: None,
        run: attributes_service_name_span_attribute,
    },
    // The resource `service.name` resolves the span service; a matching configured
    // version is applied.
    MappingCase {
        name: "resource__service_name_resolution",
        configure: None,
        resource: Some(resource_service_name_resolution_res),
        run: ignored_name_span,
    },
    // Span type inference and lookup precedence
    MappingCase {
        name: "span_type__span_attribute",
        configure: None,
        resource: None,
        run: span_type_attribute,
    },
    // `span.type` is read from the resource attributes as well.
    MappingCase {
        name: "span_type__resource_attribute",
        configure: None,
        resource: Some(span_type_resource_attribute_resource),
        run: ignored_name_span,
    },
    MappingCase {
        name: "span_type__db_lookup_table",
        configure: None,
        resource: None,
        run: db_types,
    },
    MappingCase {
        name: "span_type__resource_beats_span_db",
        configure: None,
        resource: Some(|| resource(vec![KeyValue::new("db.system.name", "cassandra")])),
        run: |p, _| {
            emit(
                p,
                "db-conflict",
                SpanKind::Client,
                vec![KeyValue::new("db.system.name", "redis")],
            )
        },
    },
    MappingCase {
        name: "span_type__explicit_resource_beats_span",
        configure: None,
        resource: Some(|| resource(vec![KeyValue::new("span.type", "resource-type")])),
        run: |p, _| {
            emit(
                p,
                "type-conflict",
                SpanKind::Client,
                vec![
                    KeyValue::new("span.type", "span-type"),
                    KeyValue::new("db.system.name", "redis"),
                ],
            )
        },
    },
];

/// `datadog.{service,name,resource,type,version,env}` override the dedicated fields;
/// the service override keeps a `_dd.base_service` reference to the application
/// service.
fn dd_fields_all_overrides(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "dd-field-overrides",
        SpanKind::Server,
        vec![
            KeyValue::new("datadog.service", "span-service"),
            KeyValue::new("datadog.name", "span-operation"),
            KeyValue::new("datadog.resource", "span-resource"),
            KeyValue::new("datadog.type", "queue"),
            KeyValue::new("datadog.version", "3.2.1"),
            KeyValue::new("datadog.env", "span-env"),
        ],
    ));
}

/// `datadog.span.kind` overrides the API span kind with libdatadog's exact-case values.
fn dd_fields_span_kind_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "span-kind-attribute",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.span.kind", "producer")],
    ));
}

/// `datadog.span.kind` only recognizes the lowercase v0.4 values: a wrong case falls
/// back to `Internal`.
fn dd_fields_span_kind_attribute_case_sensitive(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "span-kind-attribute-case",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.span.kind", "Server")],
    ));
}

/// The Datadog convention attributes `service.name`, `operation.name`,
/// `resource.name` and `span.type` override the dedicated span fields.
fn attributes_dd_convention_fields(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("service.name", "conv-service"),
            KeyValue::new("operation.name", "conv-operation"),
            KeyValue::new("resource.name", "conv-resource"),
            KeyValue::new("span.type", "conv-type"),
        ],
    ));
}

/// `datadog.env` on the span sets the env.
fn env_version_dd_env_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.env", "span-env")],
    ));
}

fn env_version_deployment_environment_resource_res() -> Resource {
    resource(vec![KeyValue::new("deployment.environment", "prod")])
}

fn env_version_deployment_environment_name_resource_res() -> Resource {
    resource(vec![KeyValue::new(
        "deployment.environment.name",
        "staging",
    )])
}

/// `datadog.env` on the span wins over the resource's `deployment.environment.name`.
fn env_version_dd_env_beats_resource(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("datadog.env", "span-env")],
    ));
}

fn env_version_dd_env_beats_resource_res() -> Resource {
    resource(vec![KeyValue::new(
        "deployment.environment.name",
        "resource-env",
    )])
}

fn env_version_service_version_resource_res() -> Resource {
    resource(vec![KeyValue::new("service.version", "1.2.3")])
}

fn env_version_config_version_res() -> Resource {
    resource(vec![KeyValue::new("service.name", "svc-r")])
}

fn env_version_config_version_config(cfg: &mut ConfigBuilder) {
    cfg.set_version("5.5.5".to_string());
}

/// Plain `env`, `version`, `component` and `span.kind` remain v0.4 meta tags;
/// migration may promote these into dedicated fields.
fn attributes_promoted_meta_keys(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("env", "attr-env"),
            KeyValue::new("version", "9.9.9"),
            KeyValue::new("component", "my-component"),
            KeyValue::new("span.kind", "server"),
        ],
    ));
}

fn config_env_config(cfg: &mut ConfigBuilder) {
    cfg.set_env("config-env".to_string());
}

/// Empty scope values allow span values to fill protected tags; absent and
/// empty span values differ. Configured version only applies to the app service.
fn promotion_conflicts(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for scope_value in [None, Some(""), Some("scope")] {
        for span_value in [None, Some(""), Some("span")] {
            for changed_service in [false, true] {
                let scope_attrs = scope_value
                    .map(|v| vec![KeyValue::new("env", v), KeyValue::new("version", v)])
                    .unwrap_or_default();
                let scope = InstrumentationScope::builder("promotions")
                    .with_attributes(scope_attrs)
                    .build();
                let mut attrs = vec![
                    KeyValue::new("datadog.env", "dd-env"),
                    KeyValue::new("datadog.version", "dd-version"),
                ];
                if let Some(value) = span_value {
                    attrs.extend([KeyValue::new("env", value), KeyValue::new("version", value)]);
                }
                if changed_service {
                    attrs.push(KeyValue::new("datadog.service", "other-service"));
                }
                drop(
                    SpanBuilder::from_name(format!(
                        "scope={scope_value:?},span={span_value:?},changed={changed_service}"
                    ))
                    .with_attributes(attrs)
                    .start(&provider.tracer_with_scope(scope)),
                );
            }
        }
    }
}

fn empty_promoted_tags(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for (label, attrs) in [
        ("absent", vec![]),
        (
            "empty-dd",
            vec![
                KeyValue::new("datadog.env", ""),
                KeyValue::new("datadog.version", ""),
            ],
        ),
        (
            "empty-conventional",
            vec![KeyValue::new("env", ""), KeyValue::new("version", "")],
        ),
        (
            "nonempty-conventional",
            vec![
                KeyValue::new("env", "span-env"),
                KeyValue::new("version", "span-version"),
            ],
        ),
        (
            "nonempty-dd",
            vec![
                KeyValue::new("datadog.env", "dd-env"),
                KeyValue::new("datadog.version", "dd-version"),
            ],
        ),
        (
            "numeric-conventional",
            vec![KeyValue::new("env", 42), KeyValue::new("version", 43)],
        ),
    ] {
        emit(provider, label, SpanKind::Internal, attrs);
    }
}

/// A `service.name` span attribute overrides the service; the application service
/// is kept in `_dd.base_service`.
fn attributes_service_name_span_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("service.name", "span-svc")],
    ));
}

fn resource_service_name_resolution_res() -> Resource {
    resource(vec![KeyValue::new("service.name", "otel-svc")])
}

/// The `span.type` attribute overrides the inferred span type.
fn span_type_attribute(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("span.type", "queue")],
    ));
}

fn span_type_resource_attribute_resource() -> Resource {
    resource(vec![KeyValue::new("span.type", "custom-resource-type")])
}

/// All exact-case DB lookup entries, plus known semconv values with no dedicated rule.
fn db_types(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for system in [
        "other_sql",
        "mssql",
        "mysql",
        "oracle",
        "db2",
        "postgresql",
        "redshift",
        "cloudscape",
        "hsqldb",
        "maxdb",
        "ingres",
        "firstsql",
        "edb",
        "cache",
        "firebird",
        "derby",
        "informix",
        "mariadb",
        "sqlite",
        "sybase",
        "teradata",
        "vertica",
        "h2",
        "coldfusion",
        "cockroachdb",
        "progress",
        "hanadb",
        "adabas",
        "filemaker",
        "instantdb",
        "interbase",
        "netezza",
        "pervasive",
        "pointbase",
        "clickhouse",
        "cassandra",
        "redis",
        "memcached",
        "mongodb",
        "elasticsearch",
        "opensearch",
        "hive",
        "hbase",
        "neo4j",
        "couchbase",
        "couchdb",
        "cosmosdb",
        "dynamodb",
        "geode",
        "mssqlcompact",
        "spanner",
        "trino",
        "Cassandra",
    ] {
        emit(
            provider,
            system,
            SpanKind::Client,
            vec![KeyValue::new("db.system.name", system)],
        );
    }
}

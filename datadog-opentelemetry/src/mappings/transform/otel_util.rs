// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::fmt::Write as _;

use bumpalo::Bump;

use super::{attribute_keys::*, semconv_shim};

use opentelemetry::{trace::SpanKind, Value};
use opentelemetry_semantic_conventions::{self as semconv};

/// The Span trait is used to implement utils function is a way that is generic
/// and could be ported to multiple Span models
///
/// String-returning methods either borrow from the span data (lifetime `'a`) or
/// format into the arena returned by [`OtelSpan::alloc`], so they never allocate
/// through the global allocator.
pub(crate) trait OtelSpan<'a> {
    /// Arena used to allocate formatted strings, outliving the returned `&'a str`s.
    fn alloc(&self) -> &'a Bump;
    fn name(&self) -> &'a str;
    fn span_kind(&self) -> SpanKind;
    fn has_attr(&self, attr_key: AttributeKey) -> bool;
    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<&'a str>;
    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T>;

    fn attr_len(&self) -> usize;

    fn get_attr_str(&self, attr_key: AttributeKey) -> &'a str {
        self.get_attr_str_opt(attr_key).unwrap_or("")
    }

    fn res_len(&self) -> usize;

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<&'a Value>;
}

/// `Display` wrapper that formats a string lowercased without going through
/// the global allocator.
struct Lower<'s>(&'s str);

impl std::fmt::Display for Lower<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut src = self.0;
        let mut buf = [0u8; 64];
        // Fast path: lowercase the leading ASCII run into a stack buffer.
        let mut fast_len = src
            .as_bytes()
            .iter()
            .position(|b| !b.is_ascii())
            .unwrap_or(src.len());

        loop {
            let batch_len = fast_len.min(64);
            buf[..batch_len].copy_from_slice(&src.as_bytes()[..batch_len]);
            buf[..batch_len].make_ascii_lowercase();
            if batch_len > 0 {
                // SAFETY: `buf[..batch_len]` holds a prefix of a valid `&str` whose
                // bytes are all ASCII, and ASCII lowercasing preserves UTF-8
                // validity, so it is valid UTF-8.
                f.write_str(unsafe { std::str::from_utf8_unchecked(&buf[..batch_len]) })?;
            }
            fast_len -= batch_len;
            src = &src[batch_len..];
            if src.is_empty() {
                return Ok(());
            }
            if fast_len == 0 {
                break;
            }
        }

        for c in src.chars() {
            for lc in c.to_lowercase() {
                f.write_char(lc)?;
            }
        }
        Ok(())
    }
}

/// Formats `args` into `alloc`, returning a `&str` borrowed from the arena.
pub(crate) fn fmt_in<'a>(alloc: &'a Bump, args: std::fmt::Arguments<'_>) -> &'a str {
    let mut s = bumpalo::collections::String::new_in(alloc);
    let _ = s.write_fmt(args);
    s.into_bump_str()
}

/// Returns the datadog operation name from the otel span
/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L405
pub fn get_otel_operation_name_v2<'a>(span: &impl OtelSpan<'a>) -> &'a str {
    if let Some(name) = span.get_attr_str_opt(OPERATION_NAME) {
        return name;
    }

    let is_client = matches!(span.span_kind(), SpanKind::Client);
    let is_server = matches!(span.span_kind(), SpanKind::Server);

    // http
    if span.has_attr(HTTP_METHOD) || span.has_attr(HTTP_REQUEST_METHOD) {
        if is_client {
            return "http.client.request";
        } else if is_server {
            return "http.server.request";
        }
    }

    // database
    let db_system = get_span_attributes(span, &[DB_SYSTEM, DB_SYSTEM_NAME]);
    if !db_system.is_empty() && is_client {
        return fmt_in(span.alloc(), format_args!("{}.query", Lower(db_system)));
    }

    // messaging
    let messaging_system = span.get_attr_str(MESSAGING_SYSTEM);
    let messaging_operation =
        get_span_attributes(span, &[MESSAGING_OPERATION, MESSAGING_OPERATION_TYPE]);
    if !messaging_system.is_empty()
        && !messaging_operation.is_empty()
        && matches!(
            span.span_kind(),
            SpanKind::Client | SpanKind::Server | SpanKind::Consumer | SpanKind::Producer
        )
    {
        return fmt_in(
            span.alloc(),
            format_args!("{}.{}", Lower(messaging_system), Lower(messaging_operation)),
        );
    }

    // RPC & AWS
    let rpc_system = span.get_attr_str(RPC_SYSTEM);
    let is_rpc = !rpc_system.is_empty();
    let is_aws = rpc_system == "aws-api";
    if is_client && is_aws {
        let rpc_service = span.get_attr_str(RPC_SERVICE);
        if !rpc_service.is_empty() {
            return fmt_in(
                span.alloc(),
                format_args!("aws.{}.request", Lower(rpc_service)),
            );
        }
        return "aws.client.request";
    }
    if is_client && is_rpc {
        return fmt_in(
            span.alloc(),
            format_args!("{}.client.request", Lower(rpc_system)),
        );
    }
    if is_server && is_rpc {
        return fmt_in(
            span.alloc(),
            format_args!("{}.server.request", Lower(rpc_system)),
        );
    }

    // FAAS client
    let faas_invoked_provider = span.get_attr_str(FAAS_INVOKED_PROVIDER);
    let faas_invoked_name = span.get_attr_str(FAAS_INVOKED_NAME);
    if is_client && !faas_invoked_provider.is_empty() && !faas_invoked_name.is_empty() {
        return fmt_in(
            span.alloc(),
            format_args!(
                "{}.{}.invoke",
                Lower(faas_invoked_provider),
                Lower(faas_invoked_name)
            ),
        );
    }

    // FAAS server
    let faas_trigger = span.get_attr_str(FAAS_TRIGGER);
    if !faas_trigger.is_empty() && is_server {
        return fmt_in(span.alloc(), format_args!("{}.invoke", Lower(faas_trigger)));
    }

    // GraphQL
    if !span.get_attr_str(GRAPHQL_OPERATION_TYPE).is_empty() {
        return "graphql.server.request";
    }

    // Generic HTTP server/client
    let protocol = span.get_attr_str(NETWORK_PROTOCOL_NAME);
    if is_server {
        if !protocol.is_empty() {
            return fmt_in(
                span.alloc(),
                format_args!("{}.server.request", Lower(protocol)),
            );
        }
        return "server.request";
    } else if is_client {
        if !protocol.is_empty() {
            return fmt_in(
                span.alloc(),
                format_args!("{}.client.request", Lower(protocol)),
            );
        }
        return "client.request";
    }

    // if nothing matches, checking for generic http server/client

    // Fallback in span kind
    match span.span_kind() {
        SpanKind::Client => "client",
        SpanKind::Server => "server",
        SpanKind::Producer => "producer",
        SpanKind::Consumer => "consumer",
        SpanKind::Internal => "internal",
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L332
pub fn get_otel_resource_v2<'a>(span: &impl OtelSpan<'a>) -> &'a str {
    let m = get_res_span_attributes(span, &[RESOURCE_NAME]);
    if !m.is_empty() {
        return m;
    }

    let mut m = get_res_span_attributes(span, &[HTTP_REQUEST_METHOD, HTTP_METHOD]);
    if !m.is_empty() {
        if m == "_OTHER" {
            m = "HTTP";
        }
        if matches!(span.span_kind(), SpanKind::Server) {
            let route = get_res_span_attributes(span, &[HTTP_ROUTE]);
            if !route.is_empty() {
                return fmt_in(span.alloc(), format_args!("{m} {route}"));
            }
        }
        return m;
    }

    let messaging_operation =
        get_res_span_attributes(span, &[MESSAGING_OPERATION_TYPE, MESSAGING_OPERATION]);
    if !messaging_operation.is_empty() {
        let mut res_name = messaging_operation;
        let messaging_destination =
            get_res_span_attributes(span, &[MESSAGING_DESTINATION, MESSAGING_DESTINATION_NAME]);
        if !messaging_destination.is_empty() {
            res_name = fmt_in(
                span.alloc(),
                format_args!("{res_name} {messaging_destination}"),
            );
        }
        return res_name;
    }

    let rpc_method = get_res_span_attributes(span, &[RPC_METHOD]);
    if !rpc_method.is_empty() {
        let mut res_name = rpc_method;
        let rpc_service = get_res_span_attributes(span, &[RPC_SERVICE]);
        if !rpc_service.is_empty() {
            res_name = fmt_in(span.alloc(), format_args!("{res_name} {rpc_service}"));
        }
        return res_name;
    }

    let graphql_operation_type = get_res_span_attributes(span, &[GRAPHQL_OPERATION_TYPE]);
    if !graphql_operation_type.is_empty() {
        let mut res_name = graphql_operation_type;
        let graphql_operation_name = get_res_span_attributes(span, &[GRAPHQL_OPERATION_NAME]);
        if !graphql_operation_name.is_empty() {
            res_name = fmt_in(
                span.alloc(),
                format_args!("{res_name} {graphql_operation_name}"),
            );
        }
        return res_name;
    }

    let db_system = get_res_span_attributes(span, &[DB_SYSTEM_NAME, DB_SYSTEM]);
    if !db_system.is_empty() {
        let db_statement = get_res_span_attributes(span, &[DB_STATEMENT]);
        if !db_statement.is_empty() {
            return db_statement;
        }
        let db_query = get_res_span_attributes(span, &[DB_QUERY_TEXT]);
        if !db_query.is_empty() {
            return db_query;
        }
    }
    span.name()
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L571
pub(crate) fn get_otel_status_code<'a>(span: &impl OtelSpan<'a>) -> Option<u32> {
    span.get_attr_num(HTTP_RESPONSE_STATUS_CODE)
        .or_else(|| span.get_attr_num(HTTP_STATUS_CODE))
}

const SPAN_TYPE_SQL: &str = "sql";
const SPAN_TYPE_CASSANDRA: &str = "cassandra";
const SPAN_TYPE_REDIS: &str = "redis";
const SPAN_TYPE_MEMCACHED: &str = "memcached";
const SPAN_TYPE_MONGODB: &str = "mongodb";
const SPAN_TYPE_ELASTICSEARCH: &str = "elasticsearch";
const SPAN_TYPE_OPENSEARCH: &str = "opensearch";
const SPAN_TYPE_DB: &str = "db";

macro_rules! db_mapping {
    (match $val:expr => {
        $($otel_db_type:expr => $dd_db_type:expr),* $(,)?
    }) => {
        (|| {
            $(
                if $val == $otel_db_type {
                    return Some($dd_db_type);
                }
            )*
            None
        })()
    };
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L118
fn check_db_type(db_type: &str) -> &'static str {
    let span_type = db_mapping!(match db_type => {
       semconv_shim::ATTRIBUTE_DB_SYSTEM_OTHER_SQL  => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MSSQL => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MYSQL => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_ORACLE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_DB2 => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_POSTGRESQL => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_REDSHIFT => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_CLOUDSCAPE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_HSQLDB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MAXDB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_INGRES => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_FIRSTSQL => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_EDB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_CACHE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_FIREBIRD => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_DERBY => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_INFORMIX => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MARIADB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_SQLITE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_SYBASE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_TERADATA => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_VERTICA => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_H2 => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_COLDFUSION => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_COCKROACHDB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_PROGRESS => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_HANADB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_ADABAS => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_FILEMAKER => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_INSTANTDB => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_INTERBASE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_NETEZZA => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_PERVASIVE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_POINTBASE => SPAN_TYPE_SQL,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_CLICKHOUSE => SPAN_TYPE_SQL,

        // Cassandra db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_CASSANDRA => SPAN_TYPE_CASSANDRA,

        // Redis db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_REDIS => SPAN_TYPE_REDIS,

        // Memcached db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MEMCACHED => SPAN_TYPE_MEMCACHED,

        // Mongodb db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_MONGODB => SPAN_TYPE_MONGODB,

        // Elasticsearch db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_ELASTICSEARCH => SPAN_TYPE_ELASTICSEARCH,

        // Opensearch db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_OPENSEARCH => SPAN_TYPE_OPENSEARCH,

        // Generic db types
        semconv_shim::ATTRIBUTE_DB_SYSTEM_HIVE => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_HBASE => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_NEO4J => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_COUCHBASE => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_COUCHDB => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_COSMOSDB => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_DYNAMODB => SPAN_TYPE_DB,
        semconv_shim::ATTRIBUTE_DB_SYSTEM_GEODE => SPAN_TYPE_DB,
    });
    span_type.unwrap_or(SPAN_TYPE_DB)
}

// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L250
pub fn get_otel_span_type<'a>(span: &impl OtelSpan<'a>) -> &'a str {
    let typ = get_res_span_attributes(span, &[SPAN_TYPE]);
    if !typ.is_empty() {
        return typ;
    }
    match span.span_kind() {
        SpanKind::Server => "web",
        SpanKind::Client => {
            let db = get_res_span_attributes(span, &[DB_SYSTEM_NAME, DB_SYSTEM]);
            if db.is_empty() {
                "http"
            } else {
                check_db_type(db)
            }
        }
        _ => "custom",
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L605
pub fn get_otel_env<'a>(span: &impl OtelSpan<'a>) -> &'a str {
    let datadog_env = get_res_span_attributes(span, &[DATADOG_ENV]);
    if !datadog_env.is_empty() {
        return datadog_env;
    }
    get_res_attributes(span, &[DEPLOYMENT_ENVIRONMENT_NAME, DEPLOYMENT_ENVIRONMENT])
}

pub const DEFAULT_OTLP_SERVICE_NAME: &str = "otlpresourcenoservicename";

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L272
pub fn get_otel_service<'a>(span: &impl OtelSpan<'a>) -> &'a str {
    // First, try to extract service from the span's attributes.
    if let Some(service) = span.get_attr_str_opt(SERVICE_NAME) {
        if !service.is_empty() {
            return service;
        }
    }

    // If not in span attributes, check the resource attributes.
    if let Some(service) = span.get_res_attribute_opt(SERVICE_NAME) {
        let service = super::otel_value_string_repr(service, span.alloc());
        if !service.is_empty() {
            return service;
        }
    }
    DEFAULT_OTLP_SERVICE_NAME
}

// https://github.com/DataDog/opentelemetry-mapping-go/blob/67e66831012599082cc42cf877ea340266d95bb4/pkg/otlp/attributes/attributes.go#L175
fn http_mappings(k: &str) -> Option<&'static str> {
    match k {
        semconv::attribute::CLIENT_ADDRESS => Some("http.client_ip"),
        semconv::attribute::HTTP_RESPONSE_BODY_SIZE => Some("http.response.content_length"),
        semconv::attribute::HTTP_RESPONSE_STATUS_CODE => Some("http.status_code"),
        semconv::attribute::HTTP_REQUEST_BODY_SIZE => Some("http.request.content_length"),
        "http.request.header.referrer" => Some("http.referrer"),
        semconv::attribute::HTTP_REQUEST_METHOD => Some("http.method"),
        semconv::attribute::HTTP_ROUTE => Some("http.route"),
        semconv::attribute::NETWORK_PROTOCOL_VERSION => Some("http.version"),
        semconv::attribute::SERVER_ADDRESS => Some("http.server_name"),
        semconv::attribute::URL_FULL => Some("http.url"),
        semconv::attribute::USER_AGENT_ORIGINAL => Some("http.useragent"),
        _ => None,
    }
}

fn is_datadog_convention_key(k: &str) -> bool {
    matches!(
        k,
        "service.name" | "operation.name" | "resource.name" | "span.type"
    ) || k.starts_with("datadog.")
}

/// Maps an otel attribute key to its datadog equivalent.
pub fn get_dd_key_for_otlp_attribute_in<'a>(k: &'a str, alloc: &'a Bump) -> Cow<'a, str> {
    if let Some(mapped_key) = http_mappings(k) {
        return Cow::Borrowed(mapped_key);
    }
    if let Some(suffix) = k.strip_prefix("http.request.header.") {
        return Cow::Borrowed(fmt_in(alloc, format_args!("http.request.headers.{suffix}")));
    }
    if is_datadog_convention_key(k) {
        return Cow::Borrowed("");
    }
    Cow::Borrowed(k)
}

/// Maps an otel attribute key to its datadog equivalent, for callers that don't
/// have an arena that lives long enough
///
/// TODO(paulgdc): this is here because the SampledSpan trait requires returning
/// a string with the same lifetime as the key. But the lifetime of the key
/// is never the same as the one of the bump allocator.
///
/// We should fix the SpanProperties trait in libdd-sampling and remove the duplicated
/// method
pub fn get_dd_key_for_otlp_attribute(k: &str) -> Cow<'_, str> {
    if let Some(mapped_key) = http_mappings(k) {
        return Cow::Borrowed(mapped_key);
    }
    if let Some(suffix) = k.strip_prefix("http.request.header.") {
        return Cow::Owned(format!("http.request.headers.{suffix}"));
    }
    if is_datadog_convention_key(k) {
        return Cow::Borrowed("");
    }
    Cow::Borrowed(k)
}

fn get_res_span_attributes<'a>(span: &impl OtelSpan<'a>, attributes: &[AttributeKey]) -> &'a str {
    for &attr_key in attributes {
        if let Some(res_attr) = span.get_res_attribute_opt(attr_key) {
            let res_attr = super::otel_value_string_repr(res_attr, span.alloc());
            if !res_attr.is_empty() {
                return res_attr;
            }
        };
        if let Some(attr) = span.get_attr_str_opt(attr_key) {
            return attr;
        }
    }
    ""
}

fn get_span_attributes<'a>(span: &impl OtelSpan<'a>, attributes: &[AttributeKey]) -> &'a str {
    for &attr_key in attributes {
        if let Some(attr) = span.get_attr_str_opt(attr_key) {
            if !attr.is_empty() {
                return attr;
            }
        }
    }
    ""
}

fn get_res_attributes<'a>(span: &impl OtelSpan<'a>, attributes: &[AttributeKey]) -> &'a str {
    for &attr_key in attributes {
        let Some(res_attr) = span.get_res_attribute_opt(attr_key) else {
            continue;
        };
        let res_attr = super::otel_value_string_repr(res_attr, span.alloc());
        if !res_attr.is_empty() {
            return res_attr;
        }
    }
    ""
}

#[cfg(test)]
mod lower_tests {
    use super::Lower;

    fn lowered(src: &str) -> String {
        Lower(src).to_string()
    }

    #[test]
    fn mirrors_str_to_lowercase() {
        // fast path (pure ASCII, fits in the 64-byte stack buffer)
        assert_eq!(lowered(""), "");
        assert_eq!(lowered("HTTP/2"), "http/2");
        assert_eq!(lowered("MongoDB"), "mongodb");
        // non-ASCII: downgrades to `char::to_lowercase`
        assert_eq!(lowered("Gr\u{fc}\u{df}EN"), "gr\u{fc}\u{df}en");
        assert_eq!(lowered("\u{130}"), "i\u{307}");
        // >64 bytes of ASCII: fast path is capped, remainder goes through the
        // slow path
        let long = "A".repeat(100);
        assert_eq!(lowered(&long), long.to_lowercase());
    }
}

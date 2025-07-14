// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

use super::{attribute_keys::*, semconv_shim};

use opentelemetry::{trace::SpanKind, StringValue, Value};
use opentelemetry_semantic_conventions::{self as semconv};

/// The Span trait is used to implement utils function is a way that is generic
/// and could be ported to multiple Span models
pub trait OtelSpan {
    fn name(&self) -> Cow<'static, str>;
    fn span_kind(&self) -> SpanKind;
    fn has_attr(&self, attr_key: AttributeKey) -> bool;
    fn get_attr_str_opt(&self, attr_key: AttributeKey) -> Option<Cow<'static, str>>;
    fn get_attr_num<T: TryFrom<i64>>(&self, attr_key: AttributeKey) -> Option<T>;

    fn get_attr_str(&self, attr_key: AttributeKey) -> Cow<'static, str> {
        self.get_attr_str_opt(attr_key).unwrap_or_default()
    }

    fn get_res_attribute_opt(&self, attr_key: AttributeKey) -> Option<Value>;

    fn get_res_attribute(&self, attr_key: AttributeKey) -> Value {
        self.get_res_attribute_opt(attr_key)
            .map(|v| v.to_string().into())
            .unwrap_or(Value::String(StringValue::from("")))
    }
}

/// Returns the datadog operation name from the otel span
/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L405
pub fn get_otel_operation_name_v2(span: &impl OtelSpan) -> Cow<'static, str> {
    if let Some(name) = span.get_attr_str_opt(OPERATION_NAME) {
        return name;
    }

    let is_client = matches!(span.span_kind(), SpanKind::Client);
    let is_server = matches!(span.span_kind(), SpanKind::Server);

    // http
    if span.has_attr(HTTP_REQUEST_METHOD) {
        if is_client {
            return Cow::Borrowed("http.client.request");
        } else if is_server {
            return Cow::Borrowed("http.server.request");
        }
    }

    // database
    let db_system = span.get_attr_str(DB_SYSTEM_NAME);
    if !db_system.is_empty() && is_client {
        return Cow::Owned(format!("{}.query", db_system.to_lowercase()));
    }

    // messaging
    let messaging_system = span.get_attr_str(MESSAGING_SYSTEM);
    let messaging_operation = span.get_attr_str(MESSAGING_OPERATION_TYPE);
    if !messaging_system.is_empty()
        && !messaging_operation.is_empty()
        && matches!(
            span.span_kind(),
            SpanKind::Client | SpanKind::Server | SpanKind::Consumer | SpanKind::Producer
        )
    {
        return Cow::Owned(format!("{messaging_system}.{messaging_operation}").to_lowercase());
    }

    // RPC & AWS
    let rpc_system = span.get_attr_str(RPC_SYSTEM);
    let is_rpc = !rpc_system.is_empty();
    let is_aws = rpc_system == "aws-api";
    if is_client && is_aws {
        let rpc_service = span.get_attr_str(RPC_SERVICE);
        if !rpc_service.is_empty() {
            return Cow::Owned(format!("aws.{}.request", rpc_service.to_lowercase()));
        }
        return Cow::Borrowed("aws.client.request");
    }
    if is_client && is_rpc {
        return Cow::Owned(format!("{}.client.request", rpc_system.to_lowercase()));
    }
    if is_server && is_rpc {
        return Cow::Owned(format!("{}.server.request", rpc_system.to_lowercase()));
    }

    // FAAS client
    let faas_invoked_provider = span.get_attr_str(FAAS_INVOKED_PROVIDER);
    let faas_invoked_name = span.get_attr_str(FAAS_INVOKED_NAME);
    if is_client && !faas_invoked_provider.is_empty() && !faas_invoked_name.is_empty() {
        return Cow::Owned(
            format!("{faas_invoked_provider}.{faas_invoked_name}.invoke").to_lowercase(),
        );
    }

    // FAAS server
    let faas_trigger = span.get_attr_str(FAAS_TRIGGER);
    if !faas_trigger.is_empty() && is_server {
        return Cow::Owned(format!("{}.invoke", faas_trigger.to_lowercase()));
    }

    // GraphQL
    if !span.get_attr_str(GRAPHQL_OPERATION_TYPE).is_empty() {
        return Cow::Borrowed("graphql.server.request");
    }

    // Generic HTTP server/client
    let protocol = span.get_attr_str(NETWORK_PROTOCOL_NAME);
    if is_server {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.server.request", protocol.to_lowercase()));
        }
        return Cow::Borrowed("server.request");
    } else if is_client {
        if !protocol.is_empty() {
            return Cow::Owned(format!("{}.client.request", protocol.to_lowercase()));
        }
        return Cow::Borrowed("client.request");
    }

    // if nothing matches, checking for generic http server/client

    // Fallback in span kind
    Cow::Borrowed(match span.span_kind() {
        SpanKind::Client => "client",
        SpanKind::Server => "server",
        SpanKind::Producer => "producer",
        SpanKind::Consumer => "consumer",
        SpanKind::Internal => "internal",
    })
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L332
pub fn get_otel_resource_v2(span: &impl OtelSpan) -> Cow<'static, str> {
    let m = get_res_span_attributes(span, &[RESOURCE_NAME]);
    if !m.is_empty() {
        return m;
    }

    let mut m = get_res_span_attributes(span, &[HTTP_REQUEST_METHOD]);
    if !m.is_empty() {
        if m == "_OTHER" {
            m = Cow::Borrowed("HTTP");
        }
        if matches!(span.span_kind(), SpanKind::Server) {
            let route = get_res_span_attributes(span, &[HTTP_ROUTE]);
            if !route.is_empty() {
                return Cow::Owned(format!("{m} {route}"));
            }
        }
        return m;
    }

    let messaging_operation = get_res_span_attributes(span, &[MESSAGING_OPERATION_TYPE]);
    if !messaging_operation.is_empty() {
        let mut res_name = messaging_operation;
        let messaging_destination =
            get_res_span_attributes(span, &[MESSAGING_DESTINATION, MESSAGING_DESTINATION_NAME]);
        if !messaging_destination.is_empty() {
            res_name = Cow::Owned(format!("{res_name} {messaging_destination}"));
        }
        return res_name;
    }

    let rpc_method = get_res_span_attributes(span, &[RPC_METHOD]);
    if !rpc_method.is_empty() {
        let mut res_name = rpc_method;
        let rpc_service = get_res_span_attributes(span, &[RPC_SERVICE]);
        if !rpc_service.is_empty() {
            res_name = Cow::Owned(format!("{res_name} {rpc_service}"));
        }
        return res_name;
    }

    let graphql_operation_type = get_res_span_attributes(span, &[GRAPHQL_OPERATION_TYPE]);
    if !graphql_operation_type.is_empty() {
        let mut res_name = graphql_operation_type;
        let graphql_operation_name = get_res_span_attributes(span, &[GRAPHQL_OPERATION_NAME]);
        if !graphql_operation_name.is_empty() {
            res_name = Cow::Owned(format!("{res_name} {graphql_operation_name}"));
        }
        return res_name;
    }

    let db_system = get_res_span_attributes(span, &[DB_SYSTEM_NAME]);
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
pub fn get_otel_status_code(span: &impl OtelSpan) -> u32 {
    if let Some(code) = span.get_attr_num(HTTP_RESPONSE_STATUS_CODE) {
        return code;
    }
    0
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
pub fn get_otel_span_type(span: &impl OtelSpan) -> Cow<'static, str> {
    let typ = get_res_span_attributes(span, &[SPAN_TYPE]);
    if !typ.is_empty() {
        return typ;
    }
    match span.span_kind() {
        SpanKind::Server => Cow::Borrowed("web"),
        SpanKind::Client => {
            let db = get_res_span_attributes(span, &[DB_SYSTEM_NAME]);
            if db.is_empty() {
                Cow::Borrowed("http")
            } else {
                Cow::Borrowed(check_db_type(&db))
            }
        }
        _ => Cow::Borrowed("custom"),
    }
}

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L605
pub fn get_otel_env(span: &impl OtelSpan) -> Cow<'static, str> {
    let datadog_env = get_res_span_attributes(span, &[DATADOG_ENV]);
    if !datadog_env.is_empty() {
        return datadog_env;
    }
    get_res_attributes(span, &[DEPLOYMENT_ENVIRONMENT_NAME])
}

pub const DEFAULT_OTLP_SERVICE_NAME: &str = "otlpresourcenoservicename";

/// https://github.com/DataDog/datadog-agent/blob/main/pkg/trace/traceutil/otel_util.go#L272
pub fn get_otel_service(span: &impl OtelSpan) -> Cow<'static, str> {
    // First, try to extract service from the span's attributes.
    if let Some(service) = span.get_attr_str_opt(SERVICE_NAME) {
        if !service.is_empty() {
            return service;
        }
    }

    // If not in span attributes, check the resource attributes.
    let service: Option<_> = span.get_res_attribute_opt(SERVICE_NAME);
    if let Some(service) = service {
        if !service.as_str().is_empty() {
            return Cow::Owned(service.to_string());
        }
    }
    Cow::Borrowed(DEFAULT_OTLP_SERVICE_NAME)
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

pub enum BorrowedString<'a> {
    Static(&'static str),
    Owned(String),
    Borrowed(&'a str),
}

impl BorrowedString<'_> {
    pub fn as_str(&self) -> &str {
        match self {
            BorrowedString::Static(s) => s,
            BorrowedString::Owned(s) => s,
            BorrowedString::Borrowed(s) => s,
        }
    }

    pub fn into_static_cow(self) -> Cow<'static, str> {
        match self {
            BorrowedString::Static(s) => Cow::Borrowed(s),
            BorrowedString::Owned(s) => Cow::Owned(s),
            BorrowedString::Borrowed(s) => Cow::Owned(s.to_string()),
        }
    }
}

pub fn get_dd_key_for_otlp_attribute(k: &str) -> BorrowedString {
    if let Some(mapped_key) = http_mappings(k) {
        return BorrowedString::Static(mapped_key);
    }
    if let Some(suffix) = k.strip_prefix("http.request.header.") {
        return BorrowedString::Owned(format!("http.request.headers.{suffix}"));
    }
    if is_datadog_convention_key(k) {
        return BorrowedString::Static("");
    }
    BorrowedString::Borrowed(k)
}

fn get_res_span_attributes(span: &impl OtelSpan, attributes: &[AttributeKey]) -> Cow<'static, str> {
    for &attr_key in attributes {
        let res_attr = span.get_res_attribute(attr_key);
        if !res_attr.as_str().is_empty() {
            return Cow::Owned(res_attr.to_string());
        }
        if let Some(attr) = span.get_attr_str_opt(attr_key) {
            return attr;
        }
    }
    Cow::Borrowed("")
}

fn get_res_attributes(span: &impl OtelSpan, attributes: &[AttributeKey]) -> Cow<'static, str> {
    for &attr_key in attributes {
        let Some(res_attr) = span.get_res_attribute_opt(attr_key) else {
            continue;
        };
        if !res_attr.as_str().is_empty() {
            return Cow::Owned(res_attr.to_string());
        }
    }
    Cow::Borrowed("")
}

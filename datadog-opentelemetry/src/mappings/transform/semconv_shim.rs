// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]
#![allow(missing_docs)]

//! This module contains constants for OpenTelemetry semantic conventions that are currently missing
//! in the `opentelemetry-semantic-conventions` crate.

// DB system vendors
// https://github.com/open-telemetry/opentelemetry-collector/blob/0f5d764c255eb70bc4ccdaa4438c01d5cfcd89ed/semconv/v1.26.0/generated_attribute_group.go#L1048-L1153

pub const ATTRIBUTE_DB_SYSTEM_OTHER_SQL: &str = "other_sql";
pub const ATTRIBUTE_DB_SYSTEM_MSSQL: &str = "mssql";
pub const ATTRIBUTE_DB_SYSTEM_MSSQLCOMPACT: &str = "mssqlcompact";
pub const ATTRIBUTE_DB_SYSTEM_MYSQL: &str = "mysql";
pub const ATTRIBUTE_DB_SYSTEM_ORACLE: &str = "oracle";
pub const ATTRIBUTE_DB_SYSTEM_DB2: &str = "db2";
pub const ATTRIBUTE_DB_SYSTEM_POSTGRESQL: &str = "postgresql";
pub const ATTRIBUTE_DB_SYSTEM_REDSHIFT: &str = "redshift";
pub const ATTRIBUTE_DB_SYSTEM_HIVE: &str = "hive";
pub const ATTRIBUTE_DB_SYSTEM_CLOUDSCAPE: &str = "cloudscape";
pub const ATTRIBUTE_DB_SYSTEM_HSQLDB: &str = "hsqldb";
pub const ATTRIBUTE_DB_SYSTEM_PROGRESS: &str = "progress";
pub const ATTRIBUTE_DB_SYSTEM_MAXDB: &str = "maxdb";
pub const ATTRIBUTE_DB_SYSTEM_HANADB: &str = "hanadb";
pub const ATTRIBUTE_DB_SYSTEM_INGRES: &str = "ingres";
pub const ATTRIBUTE_DB_SYSTEM_FIRSTSQL: &str = "firstsql";
pub const ATTRIBUTE_DB_SYSTEM_EDB: &str = "edb";
pub const ATTRIBUTE_DB_SYSTEM_CACHE: &str = "cache";
pub const ATTRIBUTE_DB_SYSTEM_ADABAS: &str = "adabas";
pub const ATTRIBUTE_DB_SYSTEM_FIREBIRD: &str = "firebird";
pub const ATTRIBUTE_DB_SYSTEM_DERBY: &str = "derby";
pub const ATTRIBUTE_DB_SYSTEM_FILEMAKER: &str = "filemaker";
pub const ATTRIBUTE_DB_SYSTEM_INFORMIX: &str = "informix";
pub const ATTRIBUTE_DB_SYSTEM_INSTANTDB: &str = "instantdb";
pub const ATTRIBUTE_DB_SYSTEM_INTERBASE: &str = "interbase";
pub const ATTRIBUTE_DB_SYSTEM_MARIADB: &str = "mariadb";
pub const ATTRIBUTE_DB_SYSTEM_NETEZZA: &str = "netezza";
pub const ATTRIBUTE_DB_SYSTEM_PERVASIVE: &str = "pervasive";
pub const ATTRIBUTE_DB_SYSTEM_POINTBASE: &str = "pointbase";
pub const ATTRIBUTE_DB_SYSTEM_SQLITE: &str = "sqlite";
pub const ATTRIBUTE_DB_SYSTEM_SYBASE: &str = "sybase";
pub const ATTRIBUTE_DB_SYSTEM_TERADATA: &str = "teradata";
pub const ATTRIBUTE_DB_SYSTEM_VERTICA: &str = "vertica";
pub const ATTRIBUTE_DB_SYSTEM_H2: &str = "h2";
pub const ATTRIBUTE_DB_SYSTEM_COLDFUSION: &str = "coldfusion";
pub const ATTRIBUTE_DB_SYSTEM_CASSANDRA: &str = "cassandra";
pub const ATTRIBUTE_DB_SYSTEM_HBASE: &str = "hbase";
pub const ATTRIBUTE_DB_SYSTEM_MONGODB: &str = "mongodb";
pub const ATTRIBUTE_DB_SYSTEM_REDIS: &str = "redis";
pub const ATTRIBUTE_DB_SYSTEM_COUCHBASE: &str = "couchbase";
pub const ATTRIBUTE_DB_SYSTEM_COUCHDB: &str = "couchdb";
pub const ATTRIBUTE_DB_SYSTEM_COSMOSDB: &str = "cosmosdb";
pub const ATTRIBUTE_DB_SYSTEM_DYNAMODB: &str = "dynamodb";
pub const ATTRIBUTE_DB_SYSTEM_NEO4J: &str = "neo4j";
pub const ATTRIBUTE_DB_SYSTEM_GEODE: &str = "geode";
pub const ATTRIBUTE_DB_SYSTEM_ELASTICSEARCH: &str = "elasticsearch";
pub const ATTRIBUTE_DB_SYSTEM_MEMCACHED: &str = "memcached";
pub const ATTRIBUTE_DB_SYSTEM_COCKROACHDB: &str = "cockroachdb";
pub const ATTRIBUTE_DB_SYSTEM_OPENSEARCH: &str = "opensearch";
pub const ATTRIBUTE_DB_SYSTEM_CLICKHOUSE: &str = "clickhouse";
pub const ATTRIBUTE_DB_SYSTEM_SPANNER: &str = "spanner";
pub const ATTRIBUTE_DB_SYSTEM_TRINO: &str = "trino";

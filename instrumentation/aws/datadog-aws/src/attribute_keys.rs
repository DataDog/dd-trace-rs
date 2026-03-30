// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Trace propagation payload keys.
pub(crate) const DATADOG_ATTRIBUTE_KEY: &str = "_datadog";
pub(crate) const START_TIME_KEY: &str = "x-datadog-start-time";
pub(crate) const DATADOG_RESOURCE_NAME_KEY: &str = "x-datadog-resource-name";

// AWS partition identifiers.
pub(crate) const PARTITION_AWS: &str = "aws";
pub(crate) const PARTITION_AWS_CN: &str = "aws-cn";
pub(crate) const PARTITION_AWS_GOV: &str = "aws-us-gov";
pub(crate) const PARTITION_AWS_ISO: &str = "aws-iso";
pub(crate) const PARTITION_AWS_ISO_B: &str = "aws-iso-b";
pub(crate) const PARTITION_AWS_ISO_E: &str = "aws-iso-e";
pub(crate) const PARTITION_AWS_ISO_F: &str = "aws-iso-f";

// OTel tracer name.
pub(crate) const TRACER_NAME: &str = "datadog-aws-sdk";

// Generic aws.sdk span attributes.
pub(crate) const AWS_SERVICE: &str = "aws.service";
pub(crate) const AWS_OPERATION: &str = "aws.operation";
pub(crate) const AWS_REGION: &str = "region";
pub(crate) const AWS_PARTITION: &str = "aws.partition";
pub(crate) const AWS_AGENT: &str = "aws.agent";
pub(crate) const AWS_REQUEST_ID: &str = "aws.request_id";
pub(crate) const HTTP_METHOD: &str = "http.method";
pub(crate) const HTTP_URL: &str = "http.url";
pub(crate) const HTTP_STATUS_CODE: &str = "http.status_code";
pub(crate) const COMPONENT: &str = "component";
pub(crate) const SPAN_KIND: &str = "span.kind";
pub(crate) const SERVICE_NAME: &str = "service.name";
pub(crate) const RESOURCE_NAME: &str = "resource.name";

// SQS aws.sdk span attributes.
pub(crate) const CLOUD_RESOURCE_ID: &str = "cloud.resource_id";
pub(crate) const QUEUE_NAME: &str = "queuename";
pub(crate) const MESSAGING_SYSTEM: &str = "messaging.system";

// SNS aws.sdk span attributes.
pub(crate) const TOPIC_NAME: &str = "topicname";
pub(crate) const TARGET_NAME: &str = "targetname";

// EventBridge aws.sdk span attributes.
pub(crate) const RULE_NAME: &str = "rulename";

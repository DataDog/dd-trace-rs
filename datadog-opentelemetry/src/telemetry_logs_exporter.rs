// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#![cfg(any(feature = "logs-grpc", feature = "logs-http"))]

use opentelemetry_otlp::LogExporter;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::LogBatch;

use crate::configuration::OtlpProtocol;
use crate::core::telemetry;

#[derive(Debug)]
pub struct TelemetryTrackingLogExporter {
    inner: LogExporter,
    protocol: OtlpProtocol,
}

impl TelemetryTrackingLogExporter {
    pub fn new(exporter: LogExporter, protocol: OtlpProtocol) -> Self {
        Self {
            inner: exporter,
            protocol,
        }
    }
}

impl opentelemetry_sdk::logs::LogExporter for TelemetryTrackingLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        use telemetry::TelemetryMetric::*;

        let (attempts, successes, failures, log_records) = match self.protocol {
            OtlpProtocol::Grpc => (
                OtelLogsExportAttemptsGrpc,
                OtelLogsExportSuccessesGrpc,
                OtelLogsExportFailuresGrpc,
                OtelLogRecordsGrpc,
            ),
            OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => (
                OtelLogsExportAttemptsHttp,
                OtelLogsExportSuccessesHttp,
                OtelLogsExportFailuresHttp,
                OtelLogRecordsHttp,
            ),
        };

        telemetry::add_point(1.0, attempts);

        let batch_data: Vec<_> = batch.iter().collect();
        let log_count = batch_data.len();
        let batch_ref = LogBatch::new(&batch_data);

        match self.inner.export(batch_ref).await {
            Ok(()) => {
                telemetry::add_point(1.0, successes);
                if log_count > 0 {
                    telemetry::add_point(log_count as f64, log_records);
                }
                Ok(())
            }
            Err(e) => {
                telemetry::add_point(1.0, failures);
                Err(e)
            }
        }
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        self.inner.set_resource(resource);
    }
}

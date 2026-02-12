// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::Temporality;
use std::time::Duration;

use crate::configuration::OtlpProtocol;
use crate::core::telemetry;

#[derive(Debug)]
pub struct TelemetryTrackingExporter<E> {
    inner: E,
    protocol: OtlpProtocol,
}

impl<E> TelemetryTrackingExporter<E> {
    pub fn new(exporter: E, protocol: OtlpProtocol) -> Self {
        Self {
            inner: exporter,
            protocol,
        }
    }
}

impl<E> PushMetricExporter for TelemetryTrackingExporter<E>
where
    E: PushMetricExporter,
{
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        use telemetry::TelemetryMetric::*;

        let (attempts, successes, failures) = match self.protocol {
            OtlpProtocol::Grpc => (
                OtelMetricsExportAttemptsGrpc,
                OtelMetricsExportSuccessesGrpc,
                OtelMetricsExportFailuresGrpc,
            ),
            OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson => (
                OtelMetricsExportAttemptsHttp,
                OtelMetricsExportSuccessesHttp,
                OtelMetricsExportFailuresHttp,
            ),
        };

        telemetry::add_point(1.0, attempts);

        match self.inner.export(metrics).await {
            Ok(()) => {
                telemetry::add_point(1.0, successes);
                Ok(())
            }
            Err(e) => {
                telemetry::add_point(1.0, failures);
                Err(e)
            }
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn temporality(&self) -> Temporality {
        self.inner.temporality()
    }
}

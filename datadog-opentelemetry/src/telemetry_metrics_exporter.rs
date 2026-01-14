// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::Temporality;
use std::sync::Arc;
use std::time::Duration;

use crate::core::telemetry;
use crate::metrics_exporter::OtlpProtocol;

#[cfg(feature = "metrics-http")]
use std::sync::OnceLock;

#[cfg(feature = "metrics-http")]
static HTTP_RUNTIME: OnceLock<Option<Arc<tokio::runtime::Runtime>>> = OnceLock::new();

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

    #[cfg(feature = "metrics-http")]
    fn get_http_runtime() -> Option<Arc<tokio::runtime::Runtime>> {
        HTTP_RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(Arc::new)
                .ok()
        })
        .clone()
    }

    #[cfg(feature = "metrics-http")]
    async fn export_http(
        &self,
        metrics: &ResourceMetrics,
    ) -> OTelSdkResult
    where
        E: PushMetricExporter + Send + Sync,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            return self.inner.export(metrics).await;
        }

        let Some(runtime) = Self::get_http_runtime() else {
            return self.inner.export(metrics).await;
        };

        // SAFETY: metrics valid for duration of block_on
        let metrics_ptr = metrics as *const ResourceMetrics;
        let inner = &self.inner;
        runtime.block_on(async move {
            unsafe { inner.export(&*metrics_ptr).await }
        })
    }
}

impl<E> PushMetricExporter for TelemetryTrackingExporter<E>
where
    E: PushMetricExporter + Send + Sync,
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

        #[cfg(feature = "metrics-http")]
        let result = if matches!(self.protocol, OtlpProtocol::HttpProtobuf | OtlpProtocol::HttpJson) {
            self.export_http(metrics).await
        } else {
            self.inner.export(metrics).await
        };

        #[cfg(not(feature = "metrics-http"))]
        let result = self.inner.export(metrics).await;

        match result {
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

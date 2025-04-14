// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Shared constants for the dd-trace-sampling crate

/// Sampling rate limits
pub mod rate {
    /// Default sampling rate
    pub const DEFAULT_SAMPLE_RATE: f64 = 1.0;
    /// Maximum sampling rate
    pub const MAX_SAMPLE_RATE: f64 = 1.0;
    /// Minimum sampling rate
    pub const MIN_SAMPLE_RATE: f64 = 0.0;
}

/// Pattern matching constants
pub mod pattern {
    /// Marker to represent "no rule" for a field (empty string)
    pub const NO_RULE: &str = "";
}

/// Numeric constants used in sampling algorithms
pub mod numeric {
    /// Knuth's multiplicative hash factor for deterministic sampling
    pub const KNUTH_FACTOR: u64 = 1_111_111_111_111_111_111;
    /// Maximum 64-bit unsigned integer value
    pub const MAX_UINT_64BITS: u64 = u64::MAX;
}

/// Attribute keys used in tracing
pub mod attr {
    /// Service name attribute key
    pub const SERVICE_TAG: &str = "service.name";
    /// Environment attribute key
    pub const ENV_TAG: &str = "env";
    /// Resource name attribute key
    pub const RESOURCE_TAG: &str = "resource.name";
}

/// Rule provenance categories
pub mod provenance {
    /// Customer-defined rules
    pub const CUSTOMER: &str = "customer";
    /// Dynamically loaded rules
    pub const DYNAMIC: &str = "dynamic";
    /// Default built-in rules
    pub const DEFAULT: &str = "default";
}

/// Sampling mechanism identifiers
/// 
/// These identify which mechanism was responsible for making a sampling decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SamplingMechanism {
    /// Default sampling mechanism
    Default = 0,
    
    /// Agent-side rate by service sampling
    AgentRateByService = 1,
    
    /// Remote rate sampling (deprecated)
    RemoteRate = 2,
    
    /// Local user-defined trace sampling rules
    LocalUserTraceSamplingRule = 3,
    
    /// Manual sampling (explicitly set by the user)
    Manual = 4,
    
    /// AppSec-triggered sampling
    AppSec = 5,
    
    /// Remote rate sampling - user (deprecated)
    RemoteRateUser = 6,
    
    /// Remote rate sampling - Datadog (deprecated)
    RemoteRateDatadog = 7,
    
    /// Span sampling rules
    SpanSamplingRule = 8,
    
    /// OTLP ingest probabilistic sampling (not used in dd-trace)
    OtlpIngestProbabilisticSampling = 9,
    
    /// Data jobs monitoring (not used in dd-trace)
    DataJobsMonitoring = 10,
    
    /// Remote user trace sampling rule
    RemoteUserTraceSamplingRule = 11,
    
    /// Remote dynamic trace sampling rule
    RemoteDynamicTraceSamplingRule = 12,
}

impl SamplingMechanism {
    /// Returns the numeric value of the sampling mechanism
    pub fn value(&self) -> u8 {
        *self as u8
    }
    
    /// Creates a SamplingMechanism from a numeric value
    pub fn from_value(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Default),
            1 => Some(Self::AgentRateByService),
            2 => Some(Self::RemoteRate),
            3 => Some(Self::LocalUserTraceSamplingRule),
            4 => Some(Self::Manual),
            5 => Some(Self::AppSec),
            6 => Some(Self::RemoteRateUser),
            7 => Some(Self::RemoteRateDatadog),
            8 => Some(Self::SpanSamplingRule),
            9 => Some(Self::OtlpIngestProbabilisticSampling),
            10 => Some(Self::DataJobsMonitoring),
            11 => Some(Self::RemoteUserTraceSamplingRule),
            12 => Some(Self::RemoteDynamicTraceSamplingRule),
            _ => None,
        }
    }
} 
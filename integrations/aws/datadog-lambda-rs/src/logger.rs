// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Lightweight internal logger for datadog-lambda-rs.
//!
//! Mirrors `datadog-lambda-go/internal/logger` — a standalone JSON logger
//! to stdout, decoupled from the tracer's diagnostics. Controlled by
//! `DD_LOG_LEVEL`.

use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};

/// Log level for the Lambda library's internal diagnostics.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Debug = 0,
    Warn = 1,
    Error = 2,
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(Level::Warn as u8);

#[derive(Serialize)]
struct LogEntry<'a> {
    status: &'a str,
    message: &'a str,
}

/// Set the log level. Called once during initialization based on `DD_LOG_LEVEL`.
pub(crate) fn set_level(level: Level) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Parse a `DD_LOG_LEVEL` string into a [`Level`].
pub(crate) fn parse_level(s: &str) -> Level {
    if s.eq_ignore_ascii_case("debug") {
        Level::Debug
    } else if s.eq_ignore_ascii_case("error") {
        Level::Error
    } else {
        Level::Warn
    }
}

fn log(level: Level, status: &str, message: &str) {
    let current = LOG_LEVEL.load(Ordering::Relaxed);
    if (level as u8) < current {
        return;
    }
    let prefixed = format!("datadog: {message}");
    let entry = LogEntry {
        status,
        message: &prefixed,
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        println!("{json}");
    }
}

/// Log a debug message. Only emitted when `DD_LOG_LEVEL=debug`.
macro_rules! dd_lambda_debug {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Debug, "debug", &format!($($arg)*))
    };
}

/// Log a warning message.
macro_rules! dd_lambda_warn {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Warn, "warning", &format!($($arg)*))
    };
}

/// Log an error message.
macro_rules! dd_lambda_error {
    ($($arg:tt)*) => {
        $crate::logger::_log($crate::logger::Level::Error, "error", &format!($($arg)*))
    };
}

// Public for macro access, not part of the crate API.
#[doc(hidden)]
pub(crate) fn _log(level: Level, status: &str, message: &str) {
    log(level, status, message);
}

pub(crate) use dd_lambda_debug;
pub(crate) use dd_lambda_error;
pub(crate) use dd_lambda_warn;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("debug"), Level::Debug);
        assert_eq!(parse_level("DEBUG"), Level::Debug);
        assert_eq!(parse_level("warn"), Level::Warn);
        assert_eq!(parse_level("error"), Level::Error);
        assert_eq!(parse_level("anything_else"), Level::Warn);
    }

    #[test]
    fn test_level_ordering() {
        assert!(Level::Debug < Level::Warn);
        assert!(Level::Warn < Level::Error);
    }
}

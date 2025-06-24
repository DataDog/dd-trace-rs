// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{self, Display},
    mem,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

static MAX_LOG_LEVEL: AtomicUsize = AtomicUsize::new(LogLevelFilter::Error as usize);

pub(crate) fn set_max_level(lvl: LogLevelFilter) {
    MAX_LOG_LEVEL.store(lvl as usize, Ordering::Relaxed)
}

pub fn max_level() -> LogLevelFilter {
    unsafe { mem::transmute(MAX_LOG_LEVEL.load(Ordering::Relaxed)) }
}

#[repr(usize)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[non_exhaustive]
/// The level at which the library will log
pub enum LogLevelFilter {
    Off,
    #[default]
    Error,
    Warn,
    Info,
    Debug,
}

impl FromStr for LogLevelFilter {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("debug") {
            Ok(LogLevelFilter::Debug)
        } else if s.eq_ignore_ascii_case("info") {
            Ok(LogLevelFilter::Info)
        } else if s.eq_ignore_ascii_case("warn") {
            Ok(LogLevelFilter::Warn)
        } else if s.eq_ignore_ascii_case("error") {
            Ok(LogLevelFilter::Error)
        } else if s.eq_ignore_ascii_case("off") {
            Ok(LogLevelFilter::Off)
        } else {
            Err("log level filter should be one of DEBUG, INFO, WARN, ERROR, OFF")
        }
    }
}

impl Display for LogLevelFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter = match self {
            LogLevelFilter::Debug => "DEBUG",
            LogLevelFilter::Info => "INFO",
            LogLevelFilter::Warn => "WARN",
            LogLevelFilter::Error => "ERROR",
            LogLevelFilter::Off => "OFF",
        };

        write!(f, "{filter}")
    }
}

#[repr(usize)]
#[derive(Copy, Debug, Hash)]
pub enum Level {
    Error = 1, // this value must match with LogLevelFilter::Error
    Warn,
    Info,
    Debug,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        };

        write!(f, "{level}")
    }
}

impl Clone for Level {
    #[inline]
    fn clone(&self) -> Level {
        *self
    }
}

impl PartialEq<LogLevelFilter> for Level {
    #[inline]
    fn eq(&self, other: &LogLevelFilter) -> bool {
        (*self as usize) == (*other as usize)
    }
}

impl PartialOrd<LogLevelFilter> for Level {
    #[inline]
    fn partial_cmp(&self, other: &LogLevelFilter) -> Option<std::cmp::Ordering> {
        Some((*self as usize).cmp(&(*other as usize)))
    }

    #[inline]
    fn lt(&self, other: &LogLevelFilter) -> bool {
        (*self as usize) < *other as usize
    }

    #[inline]
    fn le(&self, other: &LogLevelFilter) -> bool {
        *self as usize <= *other as usize
    }

    #[inline]
    fn gt(&self, other: &LogLevelFilter) -> bool {
        *self as usize > *other as usize
    }

    #[inline]
    fn ge(&self, other: &LogLevelFilter) -> bool {
        *self as usize >= *other as usize
    }
}

#[macro_export]
macro_rules! dd_debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => {
      $crate::dd_log!($crate::log::Level::Debug, $($arg)*)
    };
}

#[macro_export]
macro_rules! dd_info {
  // info!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::log::Level::Info, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_warn {
  // warn!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::log::Level::Warn, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_error {
  // error!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::log::Level::Error, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_log {
    ($lvl:expr, $($arg:tt)+) => {
      let lvl = $lvl;
      if lvl <= $crate::log::max_level() {
        if lvl == $crate::log::LogLevelFilter::Error {
          eprintln!("\x1b[91mERROR\x1b[0m {}:{} - {}", file!(), line!(), format!($($arg)*));
        } else {
          println!("\x1b[93m{}\x1b[0m {}:{} - {}", lvl, file!(), line!(), format!($($arg)*));
        }
      }
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        log::LogLevelFilter,
        log::{max_level, set_max_level, Level},
    };

    #[test]
    fn test_default_max_level() {
        assert!(LogLevelFilter::Error == max_level());
    }

    #[test]
    fn test_max_level() {
        let default_lvl = max_level();

        set_max_level(crate::log::LogLevelFilter::Warn);

        assert!(LogLevelFilter::Warn == max_level());
        assert!(LogLevelFilter::Debug > max_level());
        assert!(LogLevelFilter::Error < max_level());

        set_max_level(default_lvl);
    }

    #[test]
    fn test_level_and_filter() {
        const LEVELS: [Level; 4] = [Level::Error, Level::Warn, Level::Info, Level::Debug];
        const FILTERS: [LogLevelFilter; 4] = [
            LogLevelFilter::Error,
            LogLevelFilter::Warn,
            LogLevelFilter::Info,
            LogLevelFilter::Debug,
        ];

        for (lvl_index, lvl) in LEVELS.iter().enumerate() {
            assert!(*lvl > LogLevelFilter::Off);
            assert!(*lvl == FILTERS[lvl_index]);

            for filter_index in lvl_index..3 {
                assert!(*lvl < FILTERS[filter_index + 1]);
            }
        }
    }
}

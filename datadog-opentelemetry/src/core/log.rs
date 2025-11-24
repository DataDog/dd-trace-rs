// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{self, Display},
    mem,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};

static MAX_LOG_LEVEL: AtomicUsize = AtomicUsize::new(LevelFilter::Error as usize);

pub(crate) fn set_max_level(lvl: LevelFilter) {
    MAX_LOG_LEVEL.store(lvl as usize, Ordering::Relaxed)
}

pub fn max_level() -> LevelFilter {
    unsafe { mem::transmute(MAX_LOG_LEVEL.load(Ordering::Relaxed)) }
}

#[repr(usize)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[non_exhaustive]
/// The level at which the library will log
pub enum LevelFilter {
    Off,
    #[default]
    Error,
    Warn,
    Info,
    Debug,
}

impl FromStr for LevelFilter {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("debug") {
            Ok(LevelFilter::Debug)
        } else if s.eq_ignore_ascii_case("info") {
            Ok(LevelFilter::Info)
        } else if s.eq_ignore_ascii_case("warn") {
            Ok(LevelFilter::Warn)
        } else if s.eq_ignore_ascii_case("error") {
            Ok(LevelFilter::Error)
        } else if s.eq_ignore_ascii_case("off") {
            Ok(LevelFilter::Off)
        } else {
            Err("log level filter should be one of DEBUG, INFO, WARN, ERROR, OFF")
        }
    }
}

impl Display for LevelFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter = match self {
            LevelFilter::Debug => "DEBUG",
            LevelFilter::Info => "INFO",
            LevelFilter::Warn => "WARN",
            LevelFilter::Error => "ERROR",
            LevelFilter::Off => "OFF",
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

impl PartialEq<LevelFilter> for Level {
    #[inline]
    fn eq(&self, other: &LevelFilter) -> bool {
        (*self as usize) == (*other as usize)
    }
}

impl PartialOrd<LevelFilter> for Level {
    #[inline]
    fn partial_cmp(&self, other: &LevelFilter) -> Option<std::cmp::Ordering> {
        Some((*self as usize).cmp(&(*other as usize)))
    }

    #[inline]
    fn lt(&self, other: &LevelFilter) -> bool {
        (*self as usize) < *other as usize
    }

    #[inline]
    fn le(&self, other: &LevelFilter) -> bool {
        *self as usize <= *other as usize
    }

    #[inline]
    fn gt(&self, other: &LevelFilter) -> bool {
        *self as usize > *other as usize
    }

    #[inline]
    fn ge(&self, other: &LevelFilter) -> bool {
        *self as usize >= *other as usize
    }
}

pub fn print_log(
    lvl: super::log::Level,
    log: fmt::Arguments,
    file: &str,
    line: u32,
    template: Option<&str>,
) {
    if lvl == super::log::LevelFilter::Error {
        eprintln!("\x1b[91m{lvl}\x1b[0m {file}:{line} - {log}");

        if let Some(template) = template {
            // we should only send the template to telemetry to not leak sensitive information
            super::telemetry::add_log_error(
                template,
                Some(format!("Error: {template}\n at {file}:{line}")),
            );
        }
    } else {
        println!("\x1b[93m{lvl}\x1b[0m {file}:{line} - {log}");
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! dd_debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => {
      $crate::dd_log!($crate::core::log::Level::Debug, $($arg)*)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! dd_info {
  // info!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::core::log::Level::Info, $($arg)*)
  };
}

#[macro_export]
#[doc(hidden)]
macro_rules! dd_warn {
  // warn!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::core::log::Level::Warn, $($arg)*)
  };
}

#[macro_export]
#[doc(hidden)]
macro_rules! dd_error {
  // error!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::core::log::Level::Error, $($arg)*)
  };
}

#[macro_export]
#[doc(hidden)]
macro_rules! dd_log {
    ($lvl:expr, $first:expr, $($rest:tt)*) => {{
      let lvl = $lvl;
      if lvl <= $crate::core::log::max_level() {
        let loc = std::panic::Location::caller();
        $crate::core::log::print_log(lvl, format_args!($first, $($rest)*), loc.file(), loc.line(), Some($first));
      }
    }};

    ($lvl:expr, $first:expr) => {
      let lvl = $lvl;
      if lvl <= $crate::core::log::max_level() {
        let loc = std::panic::Location::caller();
        $crate::core::log::print_log(lvl, format_args!($first), loc.file(), loc.line(), Some($first));
      }
    };
}

#[cfg(test)]
mod tests {
    use crate::core::{
        log::LevelFilter,
        log::{max_level, set_max_level, Level},
    };

    #[test]
    fn test_default_max_level() {
        assert!(LevelFilter::Error == max_level());
    }

    #[test]
    fn test_max_level() {
        let default_lvl = max_level();

        set_max_level(crate::core::log::LevelFilter::Warn);

        assert!(LevelFilter::Warn == max_level());
        assert!(LevelFilter::Debug > max_level());
        assert!(LevelFilter::Error < max_level());

        set_max_level(default_lvl);
    }

    #[test]
    fn test_level_and_filter() {
        const LEVELS: [Level; 4] = [Level::Error, Level::Warn, Level::Info, Level::Debug];
        const FILTERS: [LevelFilter; 4] = [
            LevelFilter::Error,
            LevelFilter::Warn,
            LevelFilter::Info,
            LevelFilter::Debug,
        ];

        for (lvl_index, lvl) in LEVELS.iter().enumerate() {
            assert!(*lvl > LevelFilter::Off);
            assert!(*lvl == FILTERS[lvl_index]);

            for filter_index in lvl_index..3 {
                assert!(*lvl < FILTERS[filter_index + 1]);
            }
        }
    }
}

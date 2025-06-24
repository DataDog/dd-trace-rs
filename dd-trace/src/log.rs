// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt, mem,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::configuration::LogLevelFilter;

static MAX_LOG_LEVEL: AtomicUsize = AtomicUsize::new(LogLevelFilter::Error as usize);

pub(crate) fn set_max_level(lvl: LogLevelFilter) {
    MAX_LOG_LEVEL.store(lvl as usize, Ordering::Relaxed)
}

pub fn max_level() -> LogLevelFilter {
    unsafe { mem::transmute(MAX_LOG_LEVEL.load(Ordering::Relaxed)) }
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
        if lvl == $crate::configuration::LogLevelFilter::Error {
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
        configuration::LogLevelFilter,
        log::{max_level, set_max_level, Level},
    };

    #[test]
    fn test_default_max_level() {
        assert!(LogLevelFilter::Error == max_level());
    }

    #[test]
    fn test_max_level() {
        let default_lvl = max_level();

        set_max_level(crate::configuration::LogLevelFilter::Warn);

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

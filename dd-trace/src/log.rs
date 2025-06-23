// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    mem,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::configuration::LogLevel;

static MAX_LOG_LEVEL: AtomicUsize = AtomicUsize::new(LogLevel::Error as usize);

pub(crate) fn set_max_level(lvl: LogLevel) {
    MAX_LOG_LEVEL.store(lvl as usize, Ordering::Relaxed)
}

pub fn max_level() -> LogLevel {
    unsafe { mem::transmute(MAX_LOG_LEVEL.load(Ordering::Relaxed)) }
}

#[macro_export]
macro_rules! dd_debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => {
      $crate::dd_log!($crate::configuration::LogLevel::Debug, $($arg)*)
    };
}

#[macro_export]
macro_rules! dd_info {
  // info!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::configuration::LogLevel::Info, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_warn {
  // warn!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::configuration::LogLevel::Warn, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_error {
  // error!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!($crate::configuration::LogLevel::Error, $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_log {
    ($lvl:expr, $($arg:tt)+) => {
      let lvl = $lvl;
      if lvl <= $crate::log::max_level() {
        if lvl == $crate::configuration::LogLevel::Error {
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
        configuration::LogLevel,
        log::{max_level, set_max_level},
    };

    #[test]
    fn test_default_max_level() {
        assert!(LogLevel::Error == max_level());
    }

    #[test]
    fn test_max_level() {
        let default_lvl = max_level();

        set_max_level(crate::configuration::LogLevel::Warn);

        assert!(LogLevel::Warn == max_level());
        assert!(LogLevel::Debug > max_level());
        assert!(LogLevel::Error < max_level());

        set_max_level(default_lvl);
    }
}

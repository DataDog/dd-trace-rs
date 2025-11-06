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
#[derive(Copy, Debug, Hash, PartialEq)]
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

#[cfg(feature = "test-utils")]
pub mod test_logger {
    //! Implements a thread local, overridable logger 
    //! 
    //! Tests can locally intercept logs by calling to `activate_test_logger`
    //! 
    //! ```no_run
    //! let _log_guard = dd_trace::log::test_logger::activate_test_logger;();
    //! // whatever is logged by the dd_(level)! macros will be stored
    //! dd_trace::dd_debug!("my log");
    //! let logs = dd_trace::log::test_logger::take_test_logs().unwrap();
    //! // logs should contain (Debug, "my log")
    //! 
    //! // to see logs in threads spawned from the test, the function passed to spawn 
    //! // should be wrapped by `with_local_logger`
    //! std::thread::spawn(dd_trace::log::with_local_logger(|| {
    //!   dd_trace::dd_debug!("my log");
    //! })).join();
    //! ```
    use std::{cell::RefCell, sync::Arc};

    #[derive(Default)]
    struct TestLogger(std::sync::Mutex<Vec<(crate::log::Level, String)>>);

    pub fn print_log(
        lvl: crate::log::Level,
        log: std::fmt::Arguments,
        _file: &str,
        _line: u32,
        _template: Option<&str>,
    ) {
        let _ = LOCAL_LOGGER.try_with(|l| {
            if let Some(l) = &*l.borrow() {
                l.0.lock().unwrap().push((lvl, log.to_string()))
            }
        });
    }

    thread_local! {
        static LOCAL_LOGGER: RefCell<Option<Arc<TestLogger>>> = RefCell::new(None);
    }

    pub fn with_local_logger<F: FnOnce() -> R, R>(f: F) -> impl FnOnce() -> R {
        let logger = LOCAL_LOGGER.try_with(|l| l.borrow().clone()).ok().flatten();
        move || {
            let _guard = LoggerGuard {
                prev: LOCAL_LOGGER.replace(logger),
            };
            f()
        }
    }

    pub struct LoggerGuard {
        prev: Option<Arc<TestLogger>>,
    }

    impl Drop for LoggerGuard {
        fn drop(&mut self) {
            LOCAL_LOGGER.set(self.prev.take());
        }
    }

    pub fn activate_test_logger() -> LoggerGuard {
        let prev = LOCAL_LOGGER.replace(Some(Arc::new(TestLogger::default())));
        LoggerGuard { prev }
    }

    pub fn take_test_logs() -> Option<Vec<(crate::log::Level, String)>> {
        use std::ops::DerefMut;

        LOCAL_LOGGER
            .try_with(|l| {
                l.borrow()
                    .as_deref()
                    .map(|l| std::mem::take(l.0.lock().unwrap().deref_mut()))
            })
            .ok()
            .flatten()
    }
}

pub fn with_local_logger<F: FnOnce() -> R, R>(f: F) -> impl FnOnce() -> R {
    #[cfg(feature = "test-utils")]
    {
        test_logger::with_local_logger(f)
    }
    #[cfg(not(feature = "test-utils"))]
    {
        f
    }
}

pub fn print_log(
    lvl: crate::log::Level,
    log: fmt::Arguments,
    file: &str,
    line: u32,
    template: Option<&str>,
) {
    if lvl == crate::log::LevelFilter::Error {
        eprintln!("\x1b[91m{lvl}\x1b[0m {file}:{line} - {log}");

        if let Some(template) = template {
            // we should only send the template to telemetry to not leak sensitive information
            crate::telemetry::add_log_error(
                template,
                Some(format!("Error: {template}\n at {file}:{line}")),
            );
        }
    } else {
        println!("\x1b[93m{lvl}\x1b[0m {file}:{line} - {log}");
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
    ($lvl:expr, $first:expr, $($rest:tt)*) => {{
      let lvl = $lvl;
      if lvl <= $crate::log::max_level() {
        let loc = std::panic::Location::caller();
        $crate::log::print_log(lvl, format_args!($first, $($rest)*), loc.file(), loc.line(), Some($first));
      }
      #[cfg(feature = "test-utils")]
      {
        let loc = std::panic::Location::caller();
        $crate::log::test_logger::print_log(lvl, format_args!($first, $($rest)*), loc.file(), loc.line(), Some($first))
      }
    }};

    ($lvl:expr, $first:expr) => {
      $crate::dd_log!($lvl, $first,)
    };
}

#[cfg(test)]
mod tests {
    use crate::log::{max_level, set_max_level, test_logger, Level, LevelFilter};

    #[test]
    fn test_default_max_level() {
        assert!(LevelFilter::Error == max_level());
    }

    #[test]
    fn test_max_level() {
        let default_lvl = max_level();

        set_max_level(crate::log::LevelFilter::Warn);

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

    #[test]
    fn test_test_logger() {
        let _g = test_logger::activate_test_logger();
        dd_debug!("debug log {}", "foo");
        std::thread::spawn(test_logger::with_local_logger(|| {
            dd_warn!("debug log {}", "bar");
        }))
        .join()
        .unwrap();
        let test_logs = test_logger::take_test_logs().unwrap();
        assert_eq!(
            &test_logs,
            &[
                (Level::Debug, "debug log foo".into()),
                (Level::Warn, "debug log bar".into())
            ]
        );
    }
}

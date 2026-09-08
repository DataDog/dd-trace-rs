// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The tracer's own diagnostics: level filtering and routing.
//!
//! Call sites use the `dd_debug!` / `dd_info!` / `dd_warn!` / `dd_error!` macros, which gate on
//! `max_level` — set from `DD_LOG_LEVEL` when configuration is applied — and then hand off
//! to `print_log`. Two things happen there, independently of each other:
//!
//! - Errors are forwarded to instrumentation telemetry, always. Only the uninterpolated format
//!   template is sent, so interpolated values cannot leak.
//! - The message is emitted for humans: to a `tracing` subscriber if the application installed one,
//!   which then owns formatting, destination and filtering
//!   (`RUST_LOG=datadog_opentelemetry=debug`). If tracing cannot carry the event, the optional
//!   `log-compat` feature routes it through the `log` facade instead; without that feature it falls
//!   back to stdout/stderr, so a bare application still sees it.

use std::{
    fmt::{self, Display},
    mem,
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tracing::subscriber::NoSubscriber;

static MAX_LOG_LEVEL: AtomicUsize = AtomicUsize::new(LevelFilter::Error as usize);

pub(crate) fn set_max_level(lvl: LevelFilter) {
    MAX_LOG_LEVEL.store(lvl as usize, Ordering::Relaxed)
}

pub(crate) fn max_level() -> LevelFilter {
    unsafe { mem::transmute(MAX_LOG_LEVEL.load(Ordering::Relaxed)) }
}

#[repr(usize)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[non_exhaustive]
/// The level at which the library will log
pub enum LevelFilter {
    /// Logging is completely disabled.
    Off,
    /// Only error messages are logged.
    #[default]
    Error,
    /// Error and warning messages are logged.
    Warn,
    /// Error, warning, and informational messages are logged.
    Info,
    /// All messages including debug information are logged.
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
pub(crate) enum Level {
    Error = 1, // this value must match with LogLevelFilter::Error
    Warn,
    #[allow(dead_code)]
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

pub(crate) const LOG_TARGET: &str = env!("CARGO_CRATE_NAME");

pub(crate) fn print_log(
    lvl: Level,
    log: fmt::Arguments,
    file: &str,
    line: u32,
    template: Option<&str>,
) {
    if lvl == LevelFilter::Error {
        if let Some(template) = template {
            // we should only send the template to telemetry to not leak sensitive information
            super::telemetry::add_log_error(
                template,
                Some(format!("Error: {template}\n at {file}:{line}")),
            );
        }
    }

    emit(lvl, log, file, line);
}

/// Whether the calling thread would actually dispatch an event to a subscriber.
///
/// `tracing::dispatcher::has_been_set` cannot answer this: it reports whether a dispatcher was ever
/// installed anywhere in the process and is never cleared, so it stays true once a scoped
/// `with_default` has exited, and on threads — such as the tracer's own workers — that never had
/// one. Events emitted there reach `tracing`'s no-op dispatcher and are silently lost, exactly the
/// case the printed fallback exists for. Asking the current dispatcher what it is avoids that.
///
/// A subscriber that is installed but filters this target out is deliberately not covered: that is
/// the application's decision, and printing over it would be worse than staying quiet.
fn has_current_subscriber() -> bool {
    tracing::dispatcher::get_default(|dispatch| !dispatch.is::<NoSubscriber>())
}

/// Where a diagnostic was sent. Returned so tests can assert on the destination without capturing
/// the process's output streams; production callers ignore it.
#[derive(Debug, PartialEq, Eq)]
enum Destination {
    Subscriber,
    #[cfg(feature = "log-compat")]
    Log,
    #[cfg(not(feature = "log-compat"))]
    Streams,
}

/// This crate's level as `tracing` spells it.
const fn tracing_level(lvl: Level) -> tracing::Level {
    match lvl {
        Level::Error => tracing::Level::ERROR,
        Level::Warn => tracing::Level::WARN,
        Level::Info => tracing::Level::INFO,
        Level::Debug => tracing::Level::DEBUG,
    }
}

/// Split out from [`tracing_can_deliver`] so the comparison can be tested against ceilings other
/// than the one this build happens to have.
fn within_static_ceiling(
    level: tracing::Level,
    ceiling: tracing::level_filters::LevelFilter,
) -> bool {
    level <= ceiling
}

/// Whether `tracing` is able to carry a diagnostic at this level at all.
///
/// Two ways it cannot, each leaving the printed fallback as the only route:
///
/// - No subscriber on this thread, so the event reaches a no-op dispatcher.
/// - A compile-time ceiling below this level. Applications can enable `tracing`'s `max_level_*` or
///   `release_max_level_*` features, and because cargo features are additive that compiles our
///   callsites out. Nothing at runtime, `DD_LOG_LEVEL` included, can bring them back.
///
/// OpenTelemetry telemetry suppression does not make `tracing` itself unavailable. A suppressed
/// event must still be dispatched so non-OpenTelemetry layers can capture, format and redirect it;
/// `SdkLogger::event_enabled` independently prevents an OpenTelemetry log bridge from exporting it.
///
/// Filtering a subscriber *chooses* — by target, or by its own level hint — is deliberately not
/// covered. That is the application's policy, and printing over it would be worse than staying
/// quiet. When `log-compat` is disabled, the output streams have no compile-time ceiling and remain
/// available in both cases above; enabling it gives the `log` facade ownership of the fallback.
fn tracing_can_deliver(lvl: Level) -> bool {
    within_static_ceiling(tracing_level(lvl), tracing::level_filters::STATIC_MAX_LEVEL)
        && has_current_subscriber()
}

fn emit(lvl: Level, log: fmt::Arguments, file: &str, line: u32) -> Destination {
    if tracing_can_deliver(lvl) {
        match lvl {
            Level::Error => tracing::error!(target: LOG_TARGET, file, line, "{log}"),
            Level::Warn => tracing::warn!(target: LOG_TARGET, file, line, "{log}"),
            Level::Info => tracing::info!(target: LOG_TARGET, file, line, "{log}"),
            Level::Debug => tracing::debug!(target: LOG_TARGET, file, line, "{log}"),
        }
        Destination::Subscriber
    } else {
        emit_without_tracing(lvl, log, file, line)
    }
}

#[cfg(feature = "log-compat")]
fn emit_without_tracing(lvl: Level, message: fmt::Arguments, file: &str, line: u32) -> Destination {
    let level = match lvl {
        Level::Error => log::Level::Error,
        Level::Warn => log::Level::Warn,
        Level::Info => log::Level::Info,
        Level::Debug => log::Level::Debug,
    };
    let metadata = log::Metadata::builder()
        .level(level)
        .target(LOG_TARGET)
        .build();
    let logger = log::logger();

    if level <= log::max_level() && logger.enabled(&metadata) {
        logger.log(
            &log::Record::builder()
                .metadata(metadata)
                .args(message)
                .file(Some(file))
                .line(Some(line))
                .build(),
        );
    }

    Destination::Log
}

#[cfg(not(feature = "log-compat"))]
fn emit_without_tracing(lvl: Level, log: fmt::Arguments, file: &str, line: u32) -> Destination {
    print_to_streams(lvl, log, file, line);
    Destination::Streams
}

#[cfg(not(feature = "log-compat"))]
fn print_to_streams(lvl: Level, log: fmt::Arguments, file: &str, line: u32) {
    if lvl == LevelFilter::Error {
        eprintln!("\x1b[91m{lvl}\x1b[0m {file}:{line} - {log}");
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

    ($lvl:expr, $first:expr) => {{
      let lvl = $lvl;
      if lvl <= $crate::core::log::max_level() {
        let loc = std::panic::Location::caller();
        $crate::core::log::print_log(lvl, format_args!($first), loc.file(), loc.line(), Some($first));
      }
    }};
}

/// Serializes tests that touch process-global logging state — `MAX_LOG_LEVEL`, the `tracing`
/// dispatcher, the `log` logger — since the default `cargo test` harness runs tests as threads
/// within one process. Not reentrant: hold it at one level only.
#[cfg(test)]
pub(crate) fn global_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Captures the events the tracer emits through `tracing`, for tests in this crate that need to
/// assert on what the host application's subscriber would see.
#[cfg(test)]
pub(crate) mod test_capture {
    use super::{global_test_lock, max_level, set_max_level, LevelFilter, LOG_TARGET};
    use std::sync::{Arc, Mutex, OnceLock};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::filter::FilterFn;
    use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
    use tracing_subscriber::Layer;

    /// A single event as the host application's subscriber would see it.
    #[derive(Debug, Clone)]
    pub(crate) struct CapturedEvent {
        pub target: String,
        pub level: tracing::Level,
        pub message: String,
        pub file: Option<String>,
        pub line: Option<u64>,
        /// Whether OpenTelemetry telemetry suppression was active when the event was emitted.
        pub suppressed: bool,
    }

    #[derive(Clone, Default)]
    struct CaptureLayer {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: LayerContext<'_, S>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);

            let captured = CapturedEvent {
                target: event.metadata().target().to_owned(),
                level: *event.metadata().level(),
                message: visitor.message,
                file: visitor.file,
                line: visitor.line,
                suppressed: opentelemetry::Context::is_current_telemetry_suppressed(),
            };
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(captured);
        }
    }

    #[derive(Default)]
    struct FieldVisitor {
        message: String,
        file: Option<String>,
        line: Option<u64>,
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "file" {
                self.file = Some(value.to_owned());
            }
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "line" {
                self.line = Some(value);
            }
        }
    }

    /// Installs a capturing subscriber on the current thread and returns the events `body` emitted.
    /// Callers must already hold [`global_test_lock`]: installing even a scoped subscriber flips
    /// `tracing`'s global "a dispatcher exists" flag, which decides whether `log` records are
    /// emitted at all.
    fn capture_locked(body: impl FnOnce()) -> Vec<CapturedEvent> {
        let layer = CaptureLayer::default();
        let events = Arc::clone(&layer.events);
        install_and_run(layer, events, body)
    }

    fn install_and_run(
        layer: impl Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
        events: Arc<Mutex<Vec<CapturedEvent>>>,
        body: impl FnOnce(),
    ) -> Vec<CapturedEvent> {
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), body);
        events.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Runs `body` with a capturing subscriber installed on the current thread, and returns the
    /// events it emitted. Leaves the tracer's max level alone, so callers that do not go through
    /// the macros cannot be perturbed by a concurrent test.
    pub(crate) fn capture(body: impl FnOnce()) -> Vec<CapturedEvent> {
        let _guard = global_test_lock();
        capture_locked(body)
    }

    /// [`capture`], but the subscriber filters this crate's target out — present and listening,
    /// just not interested in us. A `FilterFn` reports no max-level hint, so this cannot perturb
    /// what a concurrent test sees.
    pub(crate) fn capture_filtered_out(body: impl FnOnce()) -> Vec<CapturedEvent> {
        let _guard = global_test_lock();
        let layer = CaptureLayer::default();
        let events = Arc::clone(&layer.events);
        let filter = FilterFn::new(|meta| meta.target() != LOG_TARGET);
        install_and_run(layer.with_filter(filter), events, body)
    }

    /// A single `log` record, as a `log`-based application would see it.
    #[derive(Debug, Clone)]
    pub(crate) struct CapturedLogRecord {
        pub target: String,
        pub level: log::Level,
        pub message: String,
        #[cfg(feature = "log-compat")]
        pub file: Option<String>,
        #[cfg(feature = "log-compat")]
        pub line: Option<u32>,
    }

    static LOG_RECORDS: Mutex<Vec<CapturedLogRecord>> = Mutex::new(Vec::new());

    struct CaptureLogger;

    impl log::Log for CaptureLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            LOG_RECORDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(CapturedLogRecord {
                    target: record.target().to_owned(),
                    level: record.level(),
                    message: record.args().to_string(),
                    #[cfg(feature = "log-compat")]
                    file: record.file().map(str::to_owned),
                    #[cfg(feature = "log-compat")]
                    line: record.line(),
                });
        }

        fn flush(&self) {}
    }

    /// Runs `body` with a global `log` logger installed and returns the records it produced under
    /// `LOG_TARGET`. Other targets are dropped, since the logger is process-global and third-party
    /// crates land in it too.
    pub(crate) fn capture_log_records(body: impl FnOnce()) -> Vec<CapturedLogRecord> {
        let _guard = global_test_lock();

        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            // Only one logger can ever be installed; if something else owns it, the caller sees no
            // records rather than the wrong ones.
            let _ = log::set_logger(&CaptureLogger);
            log::set_max_level(log::LevelFilter::Trace);
        });

        LOG_RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        body();

        LOG_RECORDS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.target == LOG_TARGET)
            .cloned()
            .collect()
    }

    /// [`capture`], with the tracer's max level set to `level` for the duration — for tests that go
    /// through the macros and so depend on the level gate.
    ///
    /// Note that `ConfigBuilder::build` also writes this global, so tests relying on a level below
    /// `Error` are only reliable under a process-per-test runner such as nextest.
    pub(crate) fn capture_at(level: LevelFilter, body: impl FnOnce()) -> Vec<CapturedEvent> {
        let _guard = global_test_lock();
        let previous = max_level();
        set_max_level(level);

        let captured = capture_locked(body);

        set_max_level(previous);
        captured
    }
}

#[cfg(test)]
mod routing_tests {
    use opentelemetry::Context;

    use super::test_capture::{capture, capture_at, capture_filtered_out, capture_log_records};
    use super::{
        emit, has_current_subscriber, print_log, within_static_ceiling, Destination, Level,
        LevelFilter, LOG_TARGET,
    };

    #[cfg(feature = "log-compat")]
    const UNAVAILABLE_DESTINATION: Destination = Destination::Log;
    #[cfg(not(feature = "log-compat"))]
    const UNAVAILABLE_DESTINATION: Destination = Destination::Streams;

    #[test]
    fn emission_after_a_scoped_subscriber_exits_uses_the_fallback() {
        let mut inside = None;
        let events = capture(|| {
            inside = Some(emit(Level::Warn, format_args!("in scope"), "a.rs", 1));
        });
        // The same call on the same thread, once the scope has gone away.
        let outside = emit(Level::Warn, format_args!("after scope"), "a.rs", 2);

        assert_eq!(inside, Some(Destination::Subscriber));
        assert!(events.iter().any(|e| e.message == "in scope"));
        assert_eq!(
            outside, UNAVAILABLE_DESTINATION,
            "the scope has exited, so nothing would receive this through tracing"
        );
    }

    #[test]
    fn emission_on_another_thread_uses_the_fallback_while_a_subscriber_is_scoped() {
        // A scoped subscriber belongs to one thread. The tracer's own workers never had one, and
        // that is where much of its diagnostics come from.
        let mut worker = None;
        let events = capture(|| {
            worker = Some(
                std::thread::spawn(|| emit(Level::Warn, format_args!("from worker"), "w.rs", 3))
                    .join()
                    .expect("worker thread panicked"),
            );
        });

        assert_eq!(worker, Some(UNAVAILABLE_DESTINATION));
        assert!(
            events.is_empty(),
            "a diagnostic from another thread cannot reach this thread's subscriber"
        );
    }

    #[test]
    fn a_static_level_ceiling_below_the_event_uses_the_fallback() {
        use tracing::level_filters::LevelFilter as Ceiling;

        // An application can compile our callsites out with tracing's `max_level_*` /
        // `release_max_level_*` features, and cargo features are additive. `DD_LOG_LEVEL` would
        // stop working in those builds if the quieter levels were still routed to `tracing`.
        assert!(!within_static_ceiling(tracing::Level::DEBUG, Ceiling::WARN));
        assert!(!within_static_ceiling(tracing::Level::INFO, Ceiling::WARN));
        assert!(within_static_ceiling(tracing::Level::WARN, Ceiling::WARN));
        assert!(within_static_ceiling(tracing::Level::ERROR, Ceiling::WARN));
        assert!(!within_static_ceiling(tracing::Level::ERROR, Ceiling::OFF));
        assert!(within_static_ceiling(tracing::Level::DEBUG, Ceiling::TRACE));
    }

    #[test]
    fn a_suppressed_scope_still_reaches_non_otel_tracing_layers() {
        // OpenTelemetry suppression makes its log bridge drop the event, but must not prevent other
        // tracing layers from capturing, formatting or redirecting the diagnostic.
        let mut destination = None;
        let events = capture(|| {
            let _suppress_guard = Context::enter_telemetry_suppressed_scope();
            destination = Some(emit(Level::Error, format_args!("suppressed"), "a.rs", 5));
        });

        assert_eq!(destination, Some(Destination::Subscriber));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "suppressed");
        assert!(events[0].suppressed);
    }

    #[test]
    fn a_subscriber_that_filters_the_event_gets_no_fallback() {
        let mut destination = None;
        let events = capture_filtered_out(|| {
            destination = Some(emit(Level::Warn, format_args!("filtered"), "a.rs", 4));
        });

        assert_eq!(
            destination,
            Some(Destination::Subscriber),
            "a subscriber is installed; whether it keeps the event is its decision, not ours"
        );
        assert!(events.is_empty(), "the filter drops it before the layer");
    }

    #[test]
    fn an_exited_scoped_subscriber_does_not_count_as_available() {
        // Once any subscriber is installed — scoped ones included — tracing's global "has been set"
        // flag stays true for the rest of the process, and it is also true on threads that never
        // had one, such as the tracer's workers. Diagnostics emitted there must be printed rather
        // than handed to the no-op dispatcher and lost.
        let inside = tracing::subscriber::with_default(
            tracing_subscriber::registry(),
            has_current_subscriber,
        );
        let outside = has_current_subscriber();

        assert!(
            inside,
            "a subscriber is in scope, so tracing owns the diagnostic"
        );
        assert!(
            !outside,
            "the scope has exited, so the printed fallback must be used"
        );
        assert!(
            tracing::dispatcher::has_been_set(),
            "precondition: the global flag stays set, which is what hid this case"
        );
    }

    #[test]
    fn every_level_reaches_the_host_subscriber_with_target_message_and_location() {
        let events = capture(|| {
            print_log(Level::Error, format_args!("boom: {}", 42), "a.rs", 1, None);
            print_log(Level::Warn, format_args!("warned"), "b.rs", 2, None);
            print_log(Level::Info, format_args!("informed"), "c.rs", 3, None);
            print_log(Level::Debug, format_args!("debugged"), "d.rs", 4, None);
        });

        assert_eq!(events.len(), 4);
        assert_eq!(LOG_TARGET, "datadog_opentelemetry");
        assert!(events.iter().all(|e| e.target == LOG_TARGET));
        assert_eq!(
            events.iter().map(|e| e.level).collect::<Vec<_>>(),
            vec![
                tracing::Level::ERROR,
                tracing::Level::WARN,
                tracing::Level::INFO,
                tracing::Level::DEBUG,
            ],
        );
        assert_eq!(events[0].message, "boom: 42");
        // The call site's location travels as fields, since the callsite metadata would only ever
        // point back at this module.
        assert_eq!(events[0].file.as_deref(), Some("a.rs"));
        assert_eq!(events[0].line, Some(1));
        assert_eq!(events[3].message, "debugged");
    }

    #[test]
    fn macro_call_sites_supply_their_own_location() {
        let events = capture_at(LevelFilter::Debug, || crate::dd_error!("from a macro"));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "from a macro");
        assert!(events[0]
            .file
            .as_deref()
            .is_some_and(|f| f.ends_with("log.rs")));
        assert!(events[0].line.is_some());
    }

    #[test]
    #[cfg(not(feature = "log-compat"))]
    fn nothing_is_routed_through_the_log_crate() {
        // Holds either way: with a subscriber installed `tracing` consumes the event, and without
        // one we print rather than hand it over. A record here would mean the diagnostic went to
        // `tracing` while nothing was listening, or that tracing's `log` feature came back — this
        // binary compiles it in via dev-dependencies even though consumers do not get it, which is
        // what makes the assertion meaningful. The manifest side is checked with
        // `cargo tree -e features,normal`.
        let records = capture_log_records(|| {
            print_log(
                Level::Warn,
                format_args!("printed instead"),
                "a.rs",
                7,
                None,
            )
        });

        let unexpected: Vec<String> = records
            .iter()
            .map(|r| format!("{} {} {}", r.target, r.level, r.message))
            .collect();
        assert!(
            unexpected.is_empty(),
            "unexpected log records: {unexpected:?}"
        );
    }

    #[test]
    #[cfg(feature = "log-compat")]
    fn log_compat_routes_to_the_log_facade_when_tracing_is_unavailable() {
        let mut destination = None;
        let records = capture_log_records(|| {
            destination = Some(emit(
                Level::Warn,
                format_args!("captured by log"),
                "caller.rs",
                17,
            ));
        });

        assert_eq!(destination, Some(Destination::Log));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, LOG_TARGET);
        assert_eq!(records[0].level, log::Level::Warn);
        assert_eq!(records[0].message, "captured by log");
        assert_eq!(records[0].file.as_deref(), Some("caller.rs"));
        assert_eq!(records[0].line, Some(17));
    }

    #[test]
    fn events_outside_the_export_path_are_not_suppressed() {
        let events = capture(|| print_log(Level::Error, format_args!("plain"), "a.rs", 1, None));

        assert_eq!(events.len(), 1);
        assert!(!events[0].suppressed);
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{
        log::LevelFilter,
        log::{global_test_lock, max_level, set_max_level, Level},
    };

    #[test]
    fn test_default_max_level() {
        // `MAX_LOG_LEVEL` is initialised from this default. The live value is deliberately not
        // asserted: it is process-global and `ConfigBuilder::build` writes it, so any other test
        // building a `Config` can change it while this one runs. `test_max_level` covers the
        // set/read round-trip under `global_test_lock`.
        assert_eq!(LevelFilter::default(), LevelFilter::Error);
    }

    #[test]
    fn test_max_level() {
        let _guard = global_test_lock();
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

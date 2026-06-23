// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Telemetry session ids. A library constructor runs once between `exec` and
//! `main`, captures inbound lineage from `_DD_ROOT_RS_SESSION_ID` /
//! `_DD_PARENT_RS_SESSION_ID` via `libc::getenv`, and installs the outbound
//! env via `libc::setenv` (or `libc::putenv_s` on Windows) so subprocesses
//! spawned via `Command::spawn` inherit it transparently. The constructor
//! runs before any user thread exists, so the `setenv` call is sound.
//!
//! Best-effort: not refreshed on bare `fork()` (`exec` resets memory and
//! re-runs the constructor; bare fork inherits the cached value). Daemons
//! and `nix::unistd::fork` callers will report the parent's session until
//! the tracer grows a `pthread_atfork` child handler.

use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use libdd_data_pipeline::trace_exporter::TelemetryInstrumentationSessions;

const ENV_ROOT_RS_SESSION_ID: &str = "_DD_ROOT_RS_SESSION_ID";
const ENV_PARENT_RS_SESSION_ID: &str = "_DD_PARENT_RS_SESSION_ID";

static CAPTURED: OnceLock<TelemetryInstrumentationSessions> = OnceLock::new();

/// Session ids for this process. Returns the value captured by the
/// constructor; falls back to a fresh env read if the constructor did not
/// run (e.g. exotic targets without `.init_array` support).
pub(crate) fn sessions_from_runtime_id(runtime_id: &str) -> TelemetryInstrumentationSessions {
    if let Some(cached) = CAPTURED.get() {
        if cached.session_id.as_deref() == Some(runtime_id) {
            return cached.clone();
        }
    }
    sessions_from_env(runtime_id, fallback_read_env)
}

#[allow(clippy::disallowed_methods)]
fn fallback_read_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

#[ctor::ctor]
fn install_lineage() {
    // Swallow any unexpected panic during library load so we never abort the
    // host process; lineage just degrades to "missing" in that case.
    let _ = std::panic::catch_unwind(install_lineage_inner);
}

fn install_lineage_inner() {
    let runtime_id = crate::core::configuration::Config::process_runtime_id();
    // SAFETY: this constructor runs once, between `exec` and `main`, before
    // any thread is spawned by the host program. `libc::{getenv, setenv,
    // putenv_s}` are sound while the process is single-threaded.
    let captured = sessions_from_env(runtime_id, |k| unsafe { libc_getenv(k) });
    let _ = CAPTURED.set(captured);
    unsafe { install_outbound_env_libc(runtime_id) };
}

/// # Safety
/// Caller must ensure no other thread is mutating the process environment
/// concurrently.
unsafe fn libc_getenv(key: &str) -> Option<String> {
    let key_c = CString::new(key).ok()?;
    let ptr = unsafe { libc::getenv(key_c.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// # Safety
/// Caller must ensure no other thread is reading or mutating the process
/// environment concurrently.
unsafe fn install_outbound_env_libc(runtime_id: &str) {
    let Ok(rid_c) = CString::new(runtime_id) else {
        return;
    };
    let root_c = c"_DD_ROOT_RS_SESSION_ID";
    let parent_c = c"_DD_PARENT_RS_SESSION_ID";

    // Preserve root inherited from an upstream parent; otherwise we become root.
    if unsafe { libc::getenv(root_c.as_ptr()) }.is_null() {
        unsafe { ll_setenv(root_c, rid_c.as_c_str()) };
    }
    unsafe { ll_setenv(parent_c, rid_c.as_c_str()) };
}

#[cfg(unix)]
unsafe fn ll_setenv(key: &CStr, value: &CStr) {
    unsafe { libc::setenv(key.as_ptr(), value.as_ptr(), 1) };
}

#[cfg(windows)]
unsafe fn ll_setenv(key: &CStr, value: &CStr) {
    unsafe { libc::putenv_s(key.as_ptr(), value.as_ptr()) };
}

fn sessions_from_env<F>(runtime_id: &str, get_env: F) -> TelemetryInstrumentationSessions
where
    F: Fn(&str) -> Option<String>,
{
    let session_id = runtime_id.to_owned();
    TelemetryInstrumentationSessions {
        root_session_id: get_env(ENV_ROOT_RS_SESSION_ID).filter(|r| r != &session_id),
        parent_session_id: get_env(ENV_PARENT_RS_SESSION_ID).filter(|p| p != &session_id),
        session_id: Some(session_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_map(items: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = items
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn no_lineage_when_env_unset() {
        let s = sessions_from_env("rid-a", env_map(&[]));
        assert_eq!(s.session_id.as_deref(), Some("rid-a"));
        assert!(s.root_session_id.is_none());
        assert!(s.parent_session_id.is_none());
    }

    #[test]
    fn drops_lineage_matching_runtime_id() {
        let s = sessions_from_env(
            "current",
            env_map(&[
                (ENV_ROOT_RS_SESSION_ID, "current"),
                (ENV_PARENT_RS_SESSION_ID, "current"),
            ]),
        );
        assert!(s.root_session_id.is_none());
        assert!(s.parent_session_id.is_none());
    }

    #[test]
    fn captures_distinct_lineage() {
        let s = sessions_from_env(
            "current",
            env_map(&[
                (ENV_ROOT_RS_SESSION_ID, "root-x"),
                (ENV_PARENT_RS_SESSION_ID, "parent-x"),
            ]),
        );
        assert_eq!(s.session_id.as_deref(), Some("current"));
        assert_eq!(s.root_session_id.as_deref(), Some("root-x"));
        assert_eq!(s.parent_session_id.as_deref(), Some("parent-x"));
    }
}

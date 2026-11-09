// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Telemetry session ids. A library constructor runs once between `exec` and
//! `main`, captures inbound lineage from `_DD_ROOT_RS_SESSION_ID` /
//! `_DD_PARENT_RS_SESSION_ID` via `libc::getenv`, and installs the outbound
//! env via `libc::setenv` (or `libc::putenv_s` on Windows) so subprocesses
//! spawned via `Command::spawn` inherit it transparently. The constructor
//! runs before any user thread exists, so the `setenv` call is sound.
//!
//! The constructor runs while the host's global allocator may not be usable
//! yet (e.g. GitHub issue #346), so anything run in a ctor needs to be allocation-free and
//! panic-free. all of
//! that lives in [`raw`]. This module runs at tracer-init time, where
//! allocating is safe: its job is materializing `raw`'s pointers into owned
//! values.
//!
//! Best-effort: not refreshed on bare `fork()` (`exec` resets memory and
//! re-runs the constructor. Bare fork inherits the cached value). Daemons
//! and `nix::unistd::fork` callers will report the parent's session until
//! the tracer grows a `pthread_atfork` child handler.

use libdd_data_pipeline::trace_exporter::TelemetryInstrumentationSessions;

mod raw;

pub(crate) use raw::runtime_id;

use crate::core::telemetry_session::raw::NullTerminatedCharArray;

const ENV_ROOT_RS_SESSION_ID: &str = "_DD_ROOT_RS_SESSION_ID";
const ENV_PARENT_RS_SESSION_ID: &str = "_DD_PARENT_RS_SESSION_ID";

/// Session ids for this process. Returns the value captured by the
/// constructor; falls back to a fresh env read if the constructor did not
/// run (e.g. exotic targets without `.init_array` support).
pub(crate) fn sessions_from_runtime_id(runtime_id: &str) -> TelemetryInstrumentationSessions {
    if let Some(captured) = raw::captured_sessions(runtime_id) {
        return TelemetryInstrumentationSessions {
            session_id: Some(runtime_id.to_owned()),
            root_session_id: captured.root.as_ref().and_then(|b| raw_to_string(b)),
            parent_session_id: captured.parent.as_ref().and_then(|b| raw_to_string(b)),
        };
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
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: this constructor runs once, between `exec` and `main`, before
        // any thread is spawned by the host program — the single-threaded
        // contract `raw::install_lineage` requires.
        unsafe { raw::install_lineage() };
    });
}

/// Materializes a raw lineage snapshot (nul-terminated, truncated to
/// `raw`'s buffer size) into an owned `String`.
fn raw_to_string(buf: &NullTerminatedCharArray) -> Option<String> {
    Some(String::from_utf8_lossy(&buf.bytes_no_null()).into_owned())
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

    #[test]
    fn ctor_state_materializes_consistently() {
        // The load-time constructor ran before this test, so its capture
        // must materialize for the process runtime id.
        let rid =
            uuid::Uuid::from_bytes(runtime_id_bytes().expect("entropy available")).to_string();
        let sessions = sessions_from_runtime_id(&rid);
        assert_eq!(sessions.session_id.as_deref(), Some(rid.as_str()));
        // A fresh process installs its own id as root lineage, which is
        // then dropped as self-referential.
        assert!(sessions.root_session_id.is_none());
    }
}

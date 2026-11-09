// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Allocation-free, panic-free core of the load-time lineage installer.
//!
//! Everything here runs between `exec` and `main`, while the process is
//! single-threaded *and* while the host's `#[global_allocator]` may not be
//! usable yet.
//!
//! Hard rules for everything in this module, on every path:
//!
//! - No Rust heap allocation (`String`, `Vec`, `format!`, `Box`, ...) and no `libc::malloc` either:
//!   everything fits in fixed-size stack buffers or inline `OnceLock` payloads.
//! - No panics: a panic formats through the global allocator, which would abort such a host
//!   regardless of the `catch_unwind` in the parent module. Failures degrade to "lineage absent"
//!   instead.
//! - No std runtime machinery: raw libc calls plus `getrandom::fill` (a syscall into a stack
//!   buffer) only.

use std::ffi::CStr;
use std::sync::OnceLock;

use uuid::fmt::Hyphenated;
use uuid::Uuid;

const ROOT_KEY: &CStr = c"_DD_ROOT_RS_SESSION_ID";
const PARENT_KEY: &CStr = c"_DD_PARENT_RS_SESSION_ID";

/// Runtime id shared with `Config::process_runtime_id`. Stored as raw UUID
/// bytes so the constructor can seed it without allocating; the `Copy`
/// payload is stored inline, so the `OnceLock` never touches the allocator.
static RUNTIME_ID_BYTES: OnceLock<[u8; 16]> = OnceLock::new();

/// Maximum length of a captured inbound lineage value, in bytes; longer
/// values are truncated.
const MAX_LINEAGE_LEN: usize = 255;

#[derive(Clone, Copy)]
pub(crate) struct NullTerminatedCharArray([u8; Self::LEN]);

impl NullTerminatedCharArray {
    const LEN: usize = MAX_LINEAGE_LEN + 1;

    fn from_bytes(src: &[u8]) -> Self {
        // Always copies at most LEN - 1 bytes, leaving a 0
        // at the end
        let bytes_copied = src.len().min(Self::LEN - 1);

        let mut buf = [0; Self::LEN];
        buf[..bytes_copied].copy_from_slice(&src[..bytes_copied]);
        Self(buf)
    }

    pub fn bytes_no_null(&self) -> &[u8] {
        // Unwrap_or here is not neccesary since by construction there is always a null,
        // but does not hurt correctness
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(Self::LEN);
        &self.0[..end]
    }
}

/// Inbound lineage captured by the constructor. Plain data (`Copy`, stored
/// inline) so the constructor can record it without allocating; doubles
/// as the read-side view for the parent module.
#[derive(Clone, Copy)]
pub(super) struct RawTelemetryInstrumentationSessions {
    /// Nul-terminated value (env values cannot contain nul), truncated to
    /// [`MAX_LINEAGE_LEN`] bytes; `None` when absent or self-referential.
    pub(super) root: Option<NullTerminatedCharArray>,
    /// Same, for `_DD_PARENT_RS_SESSION_ID`.
    pub(super) parent: Option<NullTerminatedCharArray>,
}

static LINEAGE: OnceLock<RawTelemetryInstrumentationSessions> = OnceLock::new();

/// Entropy from the operating system; `None` when unavailable.
fn random_bytes() -> Option<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

/// Raw runtime id of this process, generating it on first use. `None` only
/// when the OS entropy source is unavailable (the init-time caller owns
/// the panic policy for that case). Race-safe: concurrent losers of the
/// `set` observe the winner's bytes.
pub(crate) fn runtime_id() -> Option<Uuid> {
    if RUNTIME_ID_BYTES.get().is_none() {
        if let Some(bytes) = random_bytes() {
            let _ = RUNTIME_ID_BYTES.set(bytes);
        }
    }
    Some(Uuid::from_bytes(RUNTIME_ID_BYTES.get().copied()?))
}

/// Hyphenated lowercase form of `rid` on the stack, unlike
/// `Uuid::to_string`. Cannot panic: the buffer is exactly the 36 bytes
/// `encode_lower` requires.
fn format_hyphenated(rid: &Uuid) -> [u8; Hyphenated::LENGTH] {
    let mut buf = [0u8; Hyphenated::LENGTH];
    let _ = rid.hyphenated().encode_lower(&mut buf);
    buf
}

/// Captures inbound lineage and installs the outbound env.
///
/// # Safety
///
/// Must run exactly once, between `exec` and `main`, while the process is
/// single-threaded: `getenv`/`setenv` are not thread-safe. The parent
/// module's `#[ctor]` is the only intended caller.
pub(crate) unsafe fn install_lineage() {
    // No entropy: skip lineage entirely rather than panic, which would
    // itself allocate and abort a host whose allocator is not ready yet.
    let Some(rid) = runtime_id() else {
        return;
    };
    let rid_hyphenated = format_hyphenated(&rid);

    // Snapshot inbound lineage before any `setenv`: it may reallocate the
    // environment and invalidate `getenv` pointers.
    //
    // SAFETY: single-threaded (see fn contract).
    let lineage = unsafe {
        RawTelemetryInstrumentationSessions {
            root: snapshot_lineage(ROOT_KEY, &rid_hyphenated),
            parent: snapshot_lineage(PARENT_KEY, &rid_hyphenated),
        }
    };
    let _ = LINEAGE.set(lineage);

    // SAFETY: single-threaded (see fn contract).
    unsafe { install_outbound_env(&rid_hyphenated) };
}

/// Returns `key`'s env value in a fixed-size nul-terminated buffer, or
/// `None` when absent or equal to our own runtime id. The copy exists
/// because the value must outlive the `setenv` calls made right after
/// (which may reallocate the environment).
///
/// # Safety
///
/// Same single-threaded contract as [`install_lineage`].
unsafe fn snapshot_lineage(
    key: &CStr,
    rid_hyphenated: &[u8; 36],
) -> Option<NullTerminatedCharArray> {
    // SAFETY: single-threaded; `key` is a valid nul-terminated literal.
    let ptr = unsafe { libc::getenv(key.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `getenv` returned a valid nul-terminated string.
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();

    // Lineage pointing back at our own runtime id is dropped.
    if bytes == rid_hyphenated.as_slice() {
        return None;
    }

    Some(NullTerminatedCharArray::from_bytes(bytes))
}

/// Exports the runtime id as outbound lineage: root only when nothing was
/// inherited from an upstream parent, parent unconditionally.
///
/// # Safety
///
/// Same single-threaded contract as [`install_lineage`].
unsafe fn install_outbound_env(rid_hyphenated: &[u8; 36]) {
    let mut value_buf = [0u8; 37];
    // Both slices are 36 bytes at compile time; cannot panic.
    value_buf[..36].copy_from_slice(rid_hyphenated);
    // Cannot fail here, but stay panic-free by construction.
    let Ok(value) = CStr::from_bytes_with_nul(&value_buf) else {
        return;
    };

    // SAFETY: single-threaded
    // `setenv`/`putenv_s` copy `value` into the environment, so the stack buffer need not outlive
    // the call.
    if unsafe { libc::getenv(ROOT_KEY.as_ptr()) }.is_null() {
        unsafe { ll_setenv(ROOT_KEY, value) };
    }
    unsafe { ll_setenv(PARENT_KEY, value) };
}

#[cfg(unix)]
unsafe fn ll_setenv(key: &CStr, value: &CStr) {
    // SAFETY: valid nul-terminated strings. single-threaded process.
    unsafe { libc::setenv(key.as_ptr(), value.as_ptr(), 1) };
}

#[cfg(windows)]
unsafe fn ll_setenv(key: &CStr, value: &CStr) {
    // SAFETY: valid nul-terminated strings. single-threaded process.
    unsafe { libc::putenv_s(key.as_ptr(), value.as_ptr()) };
}

/// Captured lineage for this runtime id, or `None` when the constructor
/// has not run for it.
pub(super) fn captured_sessions(outisde_rid: &str) -> Option<RawTelemetryInstrumentationSessions> {
    let captured = LINEAGE.get()?;
    // The constructor only captures lineage for the process runtime id.
    let rid = runtime_id()?;
    (outisde_rid.as_bytes() == format_hyphenated(&rid).as_slice()).then_some(*captured)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-time path formats ids itself (stack buffers); the
    /// init-time path uses `Uuid`'s `Display`. They must agree.
    #[test]
    fn hyphenated_format_matches_uuid_display() {
        let rid = Uuid::new_v4();
        assert_eq!(
            format_hyphenated(&rid).as_slice(),
            rid.to_string().as_bytes()
        );
    }
}

// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Build-time helper for OTel thread context sharing.
// Since this is used at build time, we shouldn't gate it behind `otel-thread-ctx` or
// `target_os="linux"`, which would break cross-compiling. Instead we check at build time that the
// target is indeed Linux.

use std::path::PathBuf;
use std::process::Command;

/// Locate the `gcc-ld/` shim directory shipped with the Rust toolchain.
///
/// This directory contains an `ld.lld` wrapper that delegates to `rust-lld`.
/// Passing it via `-B` to the C compiler driver makes it discover rust-lld
/// before any system-wide lld, which
///
/// 1. Avoids the need for a system-wide LLD install.
/// 2. Picks a recent LLD that matches the Rust toolchain's LLVM version, as opposed to e.g. CentOS
///    7's LLVM7 which is too old to handle TLSDESC.
// allow: this is run at build time, so a panic is a compile error, not a runtime one
#[allow(clippy::disallowed_methods)]
fn find_rust_lld_dir() -> Option<PathBuf> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let target = std::env::var("TARGET").ok()?;

    let output = Command::new(&rustc)
        .arg("--print")
        .arg("sysroot")
        .output()
        .ok()?;

    let sysroot = std::str::from_utf8(&output.stdout).ok()?.trim();
    let dir = PathBuf::from(sysroot)
        .join("lib/rustlib")
        .join(&target)
        .join("bin/gcc-ld");

    dir.join("ld.lld").exists().then_some(dir)
}

/// Emit the instructions required for an executable to expose thread context.
// allow: this is run at build time, so a panic is a compile error, not a runtime one
#[allow(clippy::disallowed_methods)]
pub fn emit_otel_thread_ctx_build_instructions() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        panic!("thread context sharing is only supported when targeting Linux");
    }

    let out_dir = std::env::var("OUT_DIR").expect("`OUT_DIR` is always set by cargo");
    let dlist_path = format!("{out_dir}/otel-thread-ctx.dynlist");
    std::fs::write(
        &dlist_path,
        include_str!("../otel-thread-ctx-build/dynlist"),
    )
    .expect("writing the dynamic list into `OUT_DIR` must succeed");
    println!("cargo:rustc-link-arg=-Wl,--dynamic-list={dlist_path}");
}

/// Emit the instructions required for a shared library (`cdylib`/`dylib`)
/// to expose thread context.
// allow: this is run at build time, so a panic is a compile error, not a runtime one
#[allow(clippy::disallowed_methods)]
pub fn emit_otel_thread_ctx_dylib_build_instructions() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        panic!("thread context sharing is only supported when targeting Linux");
    }

    let out_dir =
        std::env::var("OUT_DIR").expect("$OUT_DIR is not set. It should always set by cargo");
    let version_script_path = format!("{out_dir}/otel-thread-ctx.version-script");
    std::fs::write(
        &version_script_path,
        include_str!("../otel-thread-ctx-build/version-script"),
    )
    .expect("writing the version script into $OUT_DIR ({out_dir}) failed");

    // Export the TLSDESC thread-local variable to the dynamic symbol table so external
    // readers (e.g. the eBPF profiler) can discover it. Rust's cdylib linker applies a
    // version script with `local: *` that hides all symbols not explicitly allowlisted,
    // and also causes lld to relax the TLSDESC access, eliminating the dynsym entry
    // entirely.
    //
    // Passing our own version script with an explicit `global:` entry for the symbol beats
    // the `local: *` wildcard and prevents that relaxation.
    //
    // Merging multiple version scripts is not supported by GNU ld, so we need lld. We
    // prefer the toolchain's bundled rust-lld (LLD 19+ since Rust 1.84) over the system
    // lld (if it even exists). If rust-lld is not found we fall back to whatever `lld` the
    // system provides.
    //
    // We use `cargo:rustc-link-arg` rather than `cargo:rustc-cdylib-link-arg` because the
    // latter is only applied to `cdylib` builds, while these instructions target both
    // `cdylib` and `dylib` crate types. Note that `cargo:rustc-link-arg` also applies to
    // the other link targets of the calling crate (bins, tests, ...), where the arguments
    // are harmless (rustc doesn't emit its own version script for executables, and the
    // bundled lld is a drop-in replacement).
    if let Some(gcc_ld_dir) = find_rust_lld_dir() {
        println!("cargo:rustc-link-arg=-B{}", gcc_ld_dir.display());
    }
    println!("cargo:rustc-link-arg=-fuse-ld=lld");
    println!("cargo:rustc-link-arg=-Wl,--version-script={version_script_path}");
}

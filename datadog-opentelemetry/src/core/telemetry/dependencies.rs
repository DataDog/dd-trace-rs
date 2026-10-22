// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The application's runtime dependencies, as recorded at build time by `build.rs`.
//!
//! The build script records one list per binary target of the application's workspace. At
//! runtime the list is picked by executable name; when the executable doesn't match any
//! binary target (e.g. it was renamed when packaged), the union of all lists is reported.
//!
//! Accuracy caveats: the list comes from `cargo tree` with the workspace packages' default
//! features, so it can differ from the actual build when features are selected on the
//! command line; and it is empty when collection failed or was disabled at build time. A
//! build-time failure is recorded as a fixed code and reported as a telemetry error log.

use std::collections::BTreeSet;

use libdd_telemetry::data::Dependency;

use crate::dd_debug;

/// A `(name, version)` pair.
type Package = (&'static str, &'static str);

/// A binary target name and its runtime dependencies.
type Binary = (&'static str, &'static [Package]);

// Defines `BINARIES` and `FAILURE` (the code of a build-time failure).
#[cfg(feature = "dependency-collection")]
include!(concat!(env!("OUT_DIR"), "/dependencies.rs"));

#[cfg(not(feature = "dependency-collection"))]
static BINARIES: &[Binary] = &[];

#[cfg(not(feature = "dependency-collection"))]
static FAILURE: Option<&str> = None;

/// Returns the runtime dependencies of the running binary.
pub(super) fn collect() -> Vec<Dependency> {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|path| path.file_stem()?.to_str().map(str::to_owned));
    let packages = select(BINARIES, exe.as_deref());
    if let Some(code) = FAILURE {
        dd_debug!("Telemetry: dependency collection failed at build time: {code}");
    }
    dd_debug!(
        "Telemetry: reporting {} dependencies recorded at build time",
        packages.len()
    );
    packages
        .into_iter()
        .map(|(name, version)| Dependency {
            name: name.to_owned(),
            version: Some(version.to_owned()),
            ..Default::default()
        })
        .collect()
}

/// The telemetry error log for a build-time collection failure, if any.
pub(super) fn build_failure() -> Option<String> {
    failure_log(FAILURE)
}

fn failure_log(failure: Option<&str>) -> Option<String> {
    // Keep the message a template: `code` comes from a fixed set defined in `build.rs`.
    failure.map(|code| format!("Telemetry: dependency collection failed at build time: {code}"))
}

/// The packages of the binary named `exe`, or the union over all binaries if there is none.
fn select(binaries: &[Binary], exe: Option<&str>) -> BTreeSet<Package> {
    if let Some((_, packages)) = binaries.iter().find(|(name, _)| Some(*name) == exe) {
        return packages.iter().copied().collect();
    }
    binaries
        .iter()
        .flat_map(|(_, packages)| packages.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[Binary] = &[
        ("server", &[("serde", "1.0.0"), ("tokio", "1.0.0")]),
        ("worker", &[("itoa", "1.0.0"), ("tokio", "1.0.0")]),
    ];

    #[test]
    fn test_select_matching_binary() {
        let packages = select(FIXTURE, Some("worker"));
        assert_eq!(
            packages,
            BTreeSet::from([("itoa", "1.0.0"), ("tokio", "1.0.0")])
        );
    }

    #[test]
    fn test_select_unknown_binary_reports_union() {
        let expected = BTreeSet::from([("itoa", "1.0.0"), ("serde", "1.0.0"), ("tokio", "1.0.0")]);
        assert_eq!(select(FIXTURE, Some("renamed")), expected);
        assert_eq!(select(FIXTURE, None), expected);
    }

    #[test]
    fn test_failure_log() {
        assert_eq!(failure_log(None), None);
        assert_eq!(
            failure_log(Some("cargo_tree_failed")).as_deref(),
            Some("Telemetry: dependency collection failed at build time: cargo_tree_failed")
        );
    }

    #[test]
    fn test_select_empty() {
        assert!(select(&[], Some("server")).is_empty());
    }

    /// The build script runs against this repository's workspace, so the list it generated
    /// must cover the example binaries that depend on this crate, and only those.
    #[cfg(feature = "dependency-collection")]
    #[test]
    fn test_generated_list_covers_workspace_binaries() {
        assert!(FAILURE.is_none(), "collection failed: {FAILURE:?}");
        let generated = BINARIES;
        let (_, http_server) = generated
            .iter()
            .find(|(name, _)| *name == "http-server")
            .expect("the propagator example's binary is recorded");
        let names: Vec<_> = http_server.iter().map(|(name, _)| *name).collect();

        assert!(names.contains(&"datadog-opentelemetry"));
        assert!(names.contains(&"hyper"));
        // Proc-macros run at build time only.
        assert!(!names.contains(&"serde_derive"));
        assert!(generated.iter().any(|(name, _)| *name == "simple_tracing"));
        // The `tools` package doesn't depend on this crate.
        assert!(!generated
            .iter()
            .any(|(name, _)| *name == "add_junit_file_attributes"));
    }
}

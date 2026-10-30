// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The application's dependencies, as recorded at build time by `build.rs`.
//!
//! The build script records the dependency graph of the workspace packages that depend on this
//! crate. At runtime, the running executable is matched to the target it was built from:
//! - a binary target reports its package's normal dependencies;
//! - a test harness (cargo names them `<target>-<hash>`), bench or example (in `examples/`) also
//!   reports the package's dev-dependencies, with the features cargo enables to build tests.
//!
//! When the executable matches no target (e.g. it was renamed when packaged), the union over the
//! packages with a binary target is reported.
//!
//! Accuracy caveats: the graph comes from `cargo tree` with the workspace packages' default
//! features, so it can differ from the actual build when features are selected on the command
//! line; the trees of all workspace packages are merged, so a package they share carries the
//! dependencies enabled by any of them; tests only report dev-dependencies that were downloaded
//! when this crate was built; and the graph is empty when collection failed or was disabled at
//! build time. A build-time failure is recorded as a fixed code and reported as a telemetry error
//! log.

use std::{collections::BTreeSet, path::Path, sync::OnceLock};

use libdd_telemetry::data::Dependency;

use crate::dd_debug;

mod graph;

use graph::{Builds, Graph, Member, Package, Recorded, Target, TargetKind};

fn recorded() -> &'static Recorded {
    static RECORDED: OnceLock<Recorded> = OnceLock::new();
    RECORDED.get_or_init(|| {
        #[cfg(dd_build_time_dependencies)]
        let recorded = include!(concat!(env!("OUT_DIR"), "/build_time_dependencies.rs"));
        #[cfg(not(dd_build_time_dependencies))]
        let recorded = Recorded::with_error(
            option_env!("DD_BUILD_TIME_DEPENDENCIES_FAILURE").unwrap_or("not_recorded"),
        );
        recorded
    })
}

pub(super) fn collect() -> Vec<Dependency> {
    let recorded = recorded();
    let exe = std::env::current_exe().ok();
    let exe = exe.as_deref().and_then(Executable::from_path);
    let packages = recorded.graph.resolve(exe.as_ref());
    if let Some(code) = &recorded.failure {
        dd_debug!("Telemetry: dependency collection failed at build time: {code}");
    }
    dd_debug!(
        "Telemetry: reporting {} dependencies recorded at build time",
        packages.len()
    );
    packages
        .into_iter()
        .map(|Package { name, version }| Dependency {
            name: name.clone(),
            version: Some(version.clone()),
            ..Default::default()
        })
        .collect()
}

pub(super) fn build_failure() -> Option<String> {
    failure_log(recorded().failure.as_deref())
}

fn failure_log(failure: Option<&str>) -> Option<String> {
    failure.map(|code| format!("Telemetry: dependency collection failed at build time: {code}"))
}

#[derive(Debug, PartialEq)]
enum Executable {
    Bin(String),
    /// A test harness, named after its target with `-` turned into `_`.
    Test(String),
    Example(String),
}

impl Executable {
    fn from_path(exe: &Path) -> Option<Self> {
        let stem = exe.file_stem()?.to_str()?;
        // Cargo appends a 16 hex digit hash to the artifacts it doesn't link under their own name.
        let unhashed = stem
            .rsplit_once('-')
            .filter(|(_, hash)| hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|(name, _)| name);
        let in_examples = exe
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| dir == "examples");
        Some(if in_examples {
            Self::Example(crate_name(unhashed.unwrap_or(stem)))
        } else if let Some(name) = unhashed {
            Self::Test(crate_name(name))
        } else {
            Self::Bin(stem.to_owned())
        })
    }

    fn is_built_from(&self, Target { name, kind }: &Target) -> bool {
        let kind = *kind;
        match self {
            Self::Bin(exe) => kind == TargetKind::Bin && name == exe,
            Self::Test(exe) => kind != TargetKind::Example && crate_name(name) == *exe,
            Self::Example(exe) => kind == TargetKind::Example && crate_name(name) == *exe,
        }
    }

    fn build(&self) -> Builds {
        match self {
            Self::Bin(_) => Builds::Bin,
            Self::Test(_) | Self::Example(_) => Builds::Test,
        }
    }
}

fn crate_name(target: &str) -> String {
    target.replace('-', "_")
}

impl Graph {
    /// The dependencies of `exe`, or the union over the packages with a binary target if it
    /// matches none.
    fn resolve(&self, exe: Option<&Executable>) -> BTreeSet<&Package> {
        let built_from = |member: &&Member| {
            exe.is_some_and(|exe| {
                member
                    .targets
                    .iter()
                    .any(|target| exe.is_built_from(target))
            })
        };
        let mut members: Vec<(&Member, Builds)> = self
            .members
            .iter()
            .filter(built_from)
            .map(|member| (member, exe.map_or(Builds::Bin, Executable::build)))
            .collect();
        if members.is_empty() {
            members = self
                .members
                .iter()
                .filter(|member| {
                    member
                        .targets
                        .iter()
                        .any(|target| target.kind == TargetKind::Bin)
                })
                .map(|member| (member, Builds::Bin))
                .collect();
        }
        members
            .into_iter()
            .flat_map(|(member, build)| self.dependencies_of(member, build))
            .collect()
    }

    fn dependencies_of(&self, member: &Member, build: Builds) -> BTreeSet<&Package> {
        let (build, mut pending) = match (build, &member.dev_dependencies) {
            (Builds::Test, Some(dev)) => (Builds::Test, [&[member.package][..], dev].concat()),
            // Without its dev-dependencies, the package's tests weren't resolved.
            _ => (Builds::Bin, vec![member.package]),
        };
        let mut seen = BTreeSet::new();
        while let Some(package) = pending.pop() {
            if !seen.insert(package) {
                continue;
            }
            let edges = self.dependencies.get(package).into_iter().flatten();
            pending.extend(
                edges
                    .filter(|(_, builds)| builds.includes(build))
                    .map(|(dependency, _)| *dependency),
            );
        }
        // A package can be its own dev-dependency, to enable features in its tests.
        seen.remove(&member.package);
        seen.into_iter()
            .filter_map(|package| self.packages.get(package))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: usize = 0;
    const WORKER: usize = 6;

    fn target(name: &str, kind: TargetKind) -> Target {
        Target {
            name: name.to_owned(),
            kind,
        }
    }

    fn graph(
        packages: &[(&str, &str)],
        dependencies: &[&[(usize, Builds)]],
        members: Vec<Member>,
    ) -> Graph {
        Graph {
            packages: packages
                .iter()
                .map(|(name, version)| Package {
                    name: (*name).to_owned(),
                    version: (*version).to_owned(),
                })
                .collect(),
            dependencies: dependencies
                .iter()
                .map(|edges| edges.iter().copied().collect())
                .collect(),
            members,
        }
    }

    /// `app` depends on this crate and `tokio`, which enables `signal-hook` in tests, and has
    /// `criterion` as a dev-dependency; `worker`'s dev-dependencies weren't downloaded.
    fn fixture() -> Graph {
        graph(
            &[
                ("app", "0.1.0"),
                ("datadog-opentelemetry", "0.5.0"),
                ("tokio", "1.0.0"),
                ("serde_derive", "1.0.0"),
                ("criterion", "0.5.0"),
                ("signal-hook", "0.3.0"),
                ("worker", "0.1.0"),
                ("itoa", "1.0.0"),
            ],
            &[
                &[(1, Builds::Both), (2, Builds::Both)],
                &[(3, Builds::Both)],
                &[(5, Builds::Test)],
                &[],
                &[(7, Builds::Test)],
                &[],
                &[(1, Builds::Bin), (7, Builds::Bin)],
                &[],
            ],
            vec![
                Member {
                    package: APP,
                    dev_dependencies: Some(vec![0, 4]),
                    targets: vec![
                        target("app", TargetKind::Bin),
                        target("app", TargetKind::Other),
                        target("api-tests", TargetKind::Other),
                        target("demo", TargetKind::Example),
                    ],
                },
                Member {
                    package: WORKER,
                    dev_dependencies: None,
                    targets: vec![target("worker-bin", TargetKind::Bin)],
                },
            ],
        )
    }

    fn names(graph: &Graph, exe: Option<&Executable>) -> BTreeSet<String> {
        graph
            .resolve(exe)
            .into_iter()
            .map(|package| package.name.clone())
            .collect()
    }

    fn resolve(path: &str) -> BTreeSet<String> {
        let exe = Executable::from_path(Path::new(path));
        names(&fixture(), exe.as_ref())
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn test_executable_from_path() {
        let exe = |path| Executable::from_path(Path::new(path));
        assert_eq!(
            exe("/usr/local/bin/my-service"),
            Some(Executable::Bin("my-service".into()))
        );
        assert_eq!(
            exe("/app/target/debug/deps/api_tests-0123456789abcdef"),
            Some(Executable::Test("api_tests".into()))
        );
        assert_eq!(
            exe("/app/target/debug/examples/my-demo"),
            Some(Executable::Example("my_demo".into()))
        );
        assert_eq!(
            exe("/app/target/debug/examples/my_demo-0123456789abcdef"),
            Some(Executable::Example("my_demo".into()))
        );
        // Not a cargo hash.
        assert_eq!(
            exe("/usr/bin/service-v2"),
            Some(Executable::Bin("service-v2".into()))
        );
    }

    #[test]
    fn test_resolve_binary() {
        assert_eq!(
            resolve("/usr/local/bin/app"),
            set(&["datadog-opentelemetry", "serde_derive", "tokio"])
        );
    }

    #[test]
    fn test_resolve_test_includes_dev_dependencies() {
        let expected = set(&[
            "criterion",
            "datadog-opentelemetry",
            "itoa",
            "serde_derive",
            "signal-hook",
            "tokio",
        ]);
        assert_eq!(
            resolve("/app/target/debug/deps/api_tests-0123456789abcdef"),
            expected
        );
        assert_eq!(
            resolve("/app/target/debug/deps/app-0123456789abcdef"),
            expected
        );
        assert_eq!(resolve("/app/target/debug/examples/demo"), expected);
    }

    #[test]
    fn test_resolve_test_without_dev_dependencies() {
        assert_eq!(
            resolve("/app/target/debug/deps/worker_bin-0123456789abcdef"),
            set(&["datadog-opentelemetry", "itoa", "serde_derive"])
        );
    }

    #[test]
    fn test_resolve_unknown_executable_reports_binaries_union() {
        let expected = set(&["datadog-opentelemetry", "itoa", "serde_derive", "tokio"]);
        assert_eq!(resolve("/usr/local/bin/renamed"), expected);
        assert_eq!(names(&fixture(), None), expected);
    }

    /// `app` doesn't depend on this crate itself, but on the workspace library `lib-a`, which
    /// does, so both are members: `app` for its binary, `lib-a` for its tests.
    #[test]
    fn test_resolve_through_workspace_library() {
        let graph = graph(
            &[
                ("app", "0.1.0"),
                ("lib-a", "0.1.0"),
                ("datadog-opentelemetry", "0.5.0"),
                ("serde_derive", "1.0.0"),
                ("anyhow", "1.0.0"),
                ("proptest", "1.0.0"),
                ("clap", "4.0.0"),
            ],
            &[
                &[(1, Builds::Both), (6, Builds::Both)],
                &[(2, Builds::Both), (4, Builds::Both), (5, Builds::Test)],
                &[(3, Builds::Both)],
                &[],
                &[],
                &[],
                &[],
            ],
            vec![
                Member {
                    package: 0,
                    dev_dependencies: Some(Vec::new()),
                    targets: vec![target("app", TargetKind::Bin)],
                },
                Member {
                    package: 1,
                    dev_dependencies: Some(vec![5]),
                    targets: vec![target("lib-a", TargetKind::Other)],
                },
            ],
        );
        let names = |exe| names(&graph, Some(&exe));

        assert_eq!(
            names(Executable::Bin("app".into())),
            set(&[
                "anyhow",
                "clap",
                "datadog-opentelemetry",
                "lib-a",
                "serde_derive"
            ])
        );
        assert_eq!(
            names(Executable::Test("lib_a".into())),
            set(&[
                "anyhow",
                "datadog-opentelemetry",
                "proptest",
                "serde_derive"
            ])
        );
    }

    #[test]
    fn test_resolve_empty() {
        assert!(Graph::default()
            .resolve(Some(&Executable::Bin("app".into())))
            .is_empty());
    }

    #[test]
    fn test_failure_log() {
        assert_eq!(failure_log(None), None);
        assert_eq!(
            failure_log(Some("cargo_tree_failed")).as_deref(),
            Some("Telemetry: dependency collection failed at build time: cargo_tree_failed")
        );
    }

    /// The build script runs against this repository's workspace, so the graph it generated
    /// must cover the packages that depend on this crate, and only those.
    #[test]
    fn test_generated_graph_covers_workspace() {
        if matches!(
            option_env!("DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED"),
            Some("false" | "0")
        ) {
            return;
        }
        let Recorded { graph, failure } = recorded();
        assert!(failure.is_none(), "collection failed: {failure:?}");
        let names = |exe: &Executable| names(graph, Some(exe));

        let http_server = names(&Executable::Bin("http-server".into()));
        assert!(http_server.contains("datadog-opentelemetry"));
        assert!(http_server.contains("hyper"));
        // Proc-macros generate code that ends up in the binary.
        assert!(http_server.contains("serde_derive"));
        assert!(!http_server.contains("criterion"));
        assert!(!names(&Executable::Bin("simple_tracing".into())).is_empty());

        // This test runs in this crate's test harness, which links its dev-dependencies.
        let exe = std::env::current_exe().expect("the test executable has a path");
        let this_test = Executable::from_path(&exe).expect("the test executable has a name");
        assert!(matches!(this_test, Executable::Test(_)));
        let this_test = names(&this_test);
        assert!(this_test.contains("criterion"));
        assert!(!this_test.contains("datadog-opentelemetry"));

        // The `tools` package doesn't depend on this crate.
        assert!(!graph.members.iter().any(|member| member
            .targets
            .iter()
            .any(|target| target.name == "add_junit_file_attributes")));
    }
}

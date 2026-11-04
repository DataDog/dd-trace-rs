// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Records the dependencies of the application being built.
//!
//! This script locates the workspace being built
//! (the application's, not this crate's), lists its binary targets with
//! `cargo metadata --no-deps` and resolves the dependency tree of each workspace package
//! that depends on this crate with `cargo tree`, twice when it has dev-dependencies: as its
//! binaries are built, and as its tests are. The trees are merged into one graph, written to
//! `$OUT_DIR/build_time_dependencies.rs` as a Rust expression the tracer includes, and from
//! which it picks the running executable's dependencies at runtime.
//!
//! Collection is best-effort: any failure yields an empty list and never fails the build.
//! Instead, the failure is recorded as a fixed code that the tracer reports as a telemetry
//! error at runtime. Setting `DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED=false` at build time skips
//! collection, and is not reported as a failure.

fn main() {
    dependencies::generate();
}

#[path = "src/core/telemetry/dependencies/graph.rs"]
mod graph;
#[path = "src/core/telemetry/dependencies/tree.rs"]
mod tree;

// allow: cargo configures build scripts through the environment
#[allow(clippy::disallowed_methods)]
mod dependencies {
    use std::{
        collections::BTreeSet,
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use serde_json::Value;

    use super::{
        graph::{Builds, Failure, Graph, Member, Recorded, Target, TargetKind},
        tree::{package_names, parse_tree, render, GraphBuilder, Tree},
    };

    const DEPENDENCY_COLLECTION_ENABLED_ENV: &str = "DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED";
    const WORKSPACE_DIR_ENV: &str = "CARGO_WORKSPACE_DIR";
    /// Set, to the failure code, when the graph couldn't be written; must match the tracer's. See
    /// `dependencies/mod.rs` recorded() function.
    const DD_BUILD_TIME_DEPENDENCIES_FAILURE_ENV: &str = "DD_BUILD_TIME_DEPENDENCIES_FAILURE";
    /// Set when the graph was written; must match the tracer's. See `dependencies/mod.rs`.
    const DD_BUILD_TIME_DEPENDENCIES_CFG: &str = "dd_build_time_dependencies";

    /// A failure and its details, which are only shown in the build output.
    type CargoError = (Failure, String);

    struct Cargo {
        path: OsString,
        workspace: PathBuf,
        target: String,
    }

    impl Cargo {
        fn run(&self, args: &[&str], failure: Failure) -> Result<String, CargoError> {
            let output = Command::new(&self.path)
                .args(args)
                .current_dir(&self.workspace)
                // Don't recurse into rustc wrappers such as `cargo auditable`.
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env("CARGO_TERM_COLOR", "never")
                .output()
                .map_err(|err| {
                    (
                        Failure::CargoUnavailable,
                        format!("failed to run cargo: {err}"),
                    )
                })?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let details = format!("`cargo {}` failed: {}", args.join(" "), stderr.trim());
                return Err((failure, details));
            }
            String::from_utf8(output.stdout).map_err(|err| (failure, err.to_string()))
        }
    }

    pub(super) fn generate() {
        println!("cargo::rerun-if-env-changed={DEPENDENCY_COLLECTION_ENABLED_ENV}");
        println!("cargo::rerun-if-env-changed={WORKSPACE_DIR_ENV}");

        let recorded = match collection_enabled().then(collect) {
            None => Recorded::default(),
            Some(Ok(graph)) => Recorded::with(graph),
            Some(Err((failure, details))) => {
                println!(
                    "cargo::warning=dependency collection failed ({}): {details}",
                    failure.code()
                );
                Recorded::with_error(failure)
            }
        };

        let out_dir = env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
        let written = fs::write(
            Path::new(&out_dir).join("build_time_dependencies.rs"),
            render(&recorded),
        );
        // The tracer only includes the file when this cfg is set, and builds that don't run this
        // script don't set it, so a missing file never fails the build.
        println!("cargo::rustc-check-cfg=cfg({DD_BUILD_TIME_DEPENDENCIES_CFG})");
        match written {
            Ok(()) => println!("cargo::rustc-cfg={DD_BUILD_TIME_DEPENDENCIES_CFG}"),
            Err(err) => {
                let code = Failure::WriteFailed.code();
                println!("cargo::warning=dependency collection failed ({code}): {err}");
                println!("cargo::rustc-env={DD_BUILD_TIME_DEPENDENCIES_FAILURE_ENV}={code}");
            }
        }
    }

    fn collection_enabled() -> bool {
        !matches!(
            env::var(DEPENDENCY_COLLECTION_ENABLED_ENV).as_deref(),
            Ok("false" | "0")
        )
    }

    fn collect() -> Result<Graph, CargoError> {
        let unavailable = |details: &str| (Failure::CargoUnavailable, details.to_owned());
        let workspace = workspace_dir().map_err(|details| (Failure::WorkspaceNotFound, details))?;
        let cargo = Cargo {
            path: env::var_os("CARGO").ok_or_else(|| unavailable("CARGO is not set"))?,
            workspace,
            target: env::var("TARGET").map_err(|_| unavailable("TARGET is not set"))?,
        };
        // The root manifest isn't a package manifest in a virtual workspace, but its
        // `[workspace.dependencies]` can still enable features of the members' dependencies.
        for file in ["Cargo.lock", "Cargo.toml"] {
            println!(
                "cargo::rerun-if-changed={}",
                cargo.workspace.join(file).display()
            );
        }

        let packages = workspace_packages(&cargo)?;
        // A package that doesn't depend on this crate yet may come to, so all are watched.
        for manifest in packages.iter().filter_map(|p| p["manifest_path"].as_str()) {
            println!("cargo::rerun-if-changed={manifest}");
        }
        let dependents = dependents(&cargo);
        let may_depend = |package: &&Value| {
            dependents.as_ref().is_none_or(|names| {
                package["name"]
                    .as_str()
                    .is_some_and(|name| names.contains(name))
            })
        };
        let mut builder = GraphBuilder::default();
        let mut tree_error = None;
        for package in packages.iter().filter(may_depend) {
            if let Err(err) = add_member(&cargo, &mut builder, package) {
                builder.graph.unresolved.extend(targets(package));
                tree_error = Some(err);
            }
        }

        if !builder.graph.members.is_empty() {
            return Ok(builder.graph);
        }
        if let Some(err) = tree_error {
            return Err(err);
        }
        println!("cargo::warning=no package of the workspace depends on this crate");
        Ok(builder.graph)
    }

    /// The root of the workspace being built:
    /// `CARGO_WORKSPACE_DIR` if set, otherwise the parent of the target directory holding
    /// `OUT_DIR`, which is the workspace root unless the target directory was moved
    /// (`--target-dir`, `CARGO_TARGET_DIR`, `build.target-dir`) or the workspace was mounted
    /// elsewhere, e.g. by `cross`. Rather than guessing, this fails when no such parent holds a
    /// `Cargo.lock`. The error is only shown in the build output, so it can name paths.
    fn workspace_dir() -> Result<PathBuf, String> {
        if let Some(value) = env::var_os(WORKSPACE_DIR_ENV) {
            let dir = PathBuf::from(&value);
            if dir.is_dir() {
                return Ok(dir);
            }
            let hint = if dir.is_relative() {
                "; set it to an absolute path, e.g. with `relative = true` in `[env]`"
            } else {
                ""
            };
            return Err(format!(
                "{WORKSPACE_DIR_ENV}={} is not a directory{hint}",
                dir.display()
            ));
        }
        let not_found = || {
            format!(
                "the target directory is not in the workspace root; set {WORKSPACE_DIR_ENV} to it"
            )
        };
        let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(not_found)?);
        // Cargo tags the root of the target directory, and also the directory of each
        // `--target` triple below it, so the first tagged ancestor isn't always the root.
        out_dir
            .ancestors()
            .filter(|dir| dir.join("CACHEDIR.TAG").is_file())
            .filter_map(Path::parent)
            .find(|dir| dir.join("Cargo.lock").is_file())
            .map(Path::to_path_buf)
            .ok_or_else(not_found)
    }

    /// The workspace packages, from `cargo metadata --no-deps`, which only reads workspace
    /// manifests and so works offline even when the dependencies of packages that aren't
    /// being built were never downloaded.
    fn workspace_packages(cargo: &Cargo) -> Result<Vec<Value>, CargoError> {
        let args = [
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--locked",
        ];
        let metadata = cargo.run(&args, Failure::CargoMetadataFailed)?;
        let mut metadata: Value = serde_json::from_str(&metadata)
            .map_err(|err| (Failure::CargoMetadataFailed, err.to_string()))?;
        match metadata["packages"].take() {
            Value::Array(packages) => Ok(packages),
            _ => Err((
                Failure::CargoMetadataFailed,
                "unexpected `cargo metadata` output".to_owned(),
            )),
        }
    }

    /// The names of the packages that depend on this crate, normally or through
    /// dev-dependencies, from one inverted `cargo tree` of the whole workspace rather than one
    /// tree per package. Features are unified across the workspace, so it may name packages
    /// that don't depend on it when built alone, which their own trees then rule out. `None`
    /// if it failed, e.g. dev-dependencies weren't downloaded or this crate is ambiguous: every
    /// package is checked then.
    fn dependents(cargo: &Cargo) -> Option<BTreeSet<String>> {
        let this_crate = concat!(env!("CARGO_PKG_NAME"), "@", env!("CARGO_PKG_VERSION"));
        let args = [
            "tree",
            "--offline",
            "--locked",
            "--workspace",
            "--edges",
            "normal,dev",
            "--invert",
            this_crate,
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--target",
            &cargo.target,
        ];
        cargo
            .run(&args, Failure::CargoTreeFailed)
            .inspect_err(|(_, details)| {
                println!("cargo::warning=checking every package: {details}")
            })
            .ok()
            .map(|output| package_names(&output))
    }

    /// Adds a workspace `package` to the graph if it depends on this crate, normally or
    /// through its dev-dependencies.
    fn add_member(
        cargo: &Cargo,
        builder: &mut GraphBuilder,
        package: &Value,
    ) -> Result<(), CargoError> {
        let Some(id) = package["id"].as_str() else {
            return Ok(());
        };
        let tree = dependency_tree(cargo, id, "normal")
            .inspect_err(|(_, details)| println!("cargo::warning=skipping {id}: {details}"))?;
        let has_dev_dependencies = package["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|dependency| dependency["kind"] == "dev");
        // Unlike `cargo build`, `cargo test` downloads the dev-dependencies, so they may be
        // missing: their tests then report the normal dependencies only.
        let dev_tree = has_dev_dependencies
            .then(|| {
                dependency_tree(cargo, id, "normal,dev")
                    .inspect_err(|(_, details)| {
                        println!("cargo::warning=dev-dependencies of {id} not recorded: {details}")
                    })
                    .ok()
            })
            .flatten();
        let this_crate = env!("CARGO_PKG_NAME");
        if !tree.contains(this_crate)
            && !dev_tree
                .as_ref()
                .is_some_and(|dev| dev.contains(this_crate))
        {
            return Ok(());
        }

        // Without dev-dependencies, tests resolve like the binaries.
        let builds = if has_dev_dependencies {
            Builds::Bin
        } else {
            Builds::Both
        };
        let root = builder.add_tree(&tree, builds);
        let dev_dependencies = if has_dev_dependencies {
            dev_tree.map(|dev_tree| {
                builder.add_tree(&dev_tree, Builds::Test);
                let dev: BTreeSet<usize> = dev_tree
                    .dev_dependencies()
                    .map(|package| builder.node(package))
                    .collect();
                dev.into_iter().collect()
            })
        } else {
            Some(Vec::new())
        };
        builder.graph.members.push(Member {
            package: root,
            dev_dependencies,
            targets: targets(package),
        });
        Ok(())
    }

    fn targets(package: &Value) -> Vec<Target> {
        package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(target)
            .collect()
    }

    /// A package target, or `None` for a build script.
    fn target(target: &Value) -> Option<Target> {
        let name = target["name"].as_str()?;
        let kinds = target["kind"].as_array()?;
        let is = |kind: &str| kinds.iter().any(|k| k == kind);
        let kind = if is("custom-build") {
            return None;
        } else if is("bin") {
            TargetKind::Bin
        } else if is("example") {
            TargetKind::Example
        } else {
            TargetKind::Other
        };
        Some(Target {
            name: name.to_owned(),
            kind,
        })
    }

    /// The dependency tree of the package `id` for the current target, following `edges`.
    /// Proc-macros and what they depend on are included, build dependencies aren't.
    fn dependency_tree(cargo: &Cargo, id: &str, edges: &str) -> Result<Tree, CargoError> {
        let args = [
            "tree",
            "--offline",
            "--locked",
            "--edges",
            edges,
            "--prefix",
            "indent",
            "--charset",
            "ascii",
            "--format",
            "{p}",
            "--target",
            &cargo.target,
            "--package",
            id,
        ];
        let output = cargo.run(&args, Failure::CargoTreeFailed)?;
        parse_tree(&output).ok_or_else(|| {
            let details = "unexpected `cargo tree` output".to_owned();
            (Failure::CargoTreeFailed, details)
        })
    }
}

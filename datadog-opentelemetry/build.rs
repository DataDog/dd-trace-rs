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

// The types of the recorded graph, shared with the tracer.
#[path = "src/core/telemetry/dependencies/graph.rs"]
mod graph;

// allow: cargo configures build scripts through the environment
#[allow(clippy::disallowed_methods)]
mod dependencies {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use serde_json::Value;

    use super::graph::{Builds, Graph, Member, Package, Recorded, Target, TargetKind};

    const ENABLED_ENV: &str = "DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED";
    const WORKSPACE_DIR_ENV: &str = "CARGO_WORKSPACE_DIR";
    /// Set when the graph was written; must match the tracer's.
    const RECORDED_CFG: &str = "dd_build_time_dependencies";
    /// Carries the failure code to the tracer when the graph couldn't be written; must match the
    /// tracer's.
    const FAILURE_ENV: &str = "DD_BUILD_TIME_DEPENDENCIES_FAILURE";
    const WRITE_FAILED: &str = "write_failed";

    #[derive(Default)]
    struct GraphBuilder {
        graph: Graph,
        index: HashMap<Package, usize>,
    }

    impl GraphBuilder {
        fn node(&mut self, package: &Package) -> usize {
            if let Some(&index) = self.index.get(package) {
                return index;
            }
            let graph = &mut self.graph;
            graph.packages.push(package.clone());
            graph.dependencies.push(BTreeMap::new());
            self.index.insert(package.clone(), graph.packages.len() - 1);
            graph.packages.len() - 1
        }

        /// Adds the non-dev edges of `tree`, seen in `builds`, and returns its root.
        fn add_tree(&mut self, tree: &Tree, builds: Builds) -> usize {
            for (parent, child, _) in tree.edges.iter().filter(|(_, _, dev)| !dev) {
                let (parent, child) = (self.node(parent), self.node(child));
                self.graph.dependencies[parent]
                    .entry(child)
                    .and_modify(|seen| *seen = seen.merge(builds))
                    .or_insert(builds);
            }
            self.node(&tree.root)
        }
    }

    struct Tree {
        root: Package,
        edges: Vec<(Package, Package, bool)>,
    }

    impl Tree {
        fn contains(&self, name: &str) -> bool {
            self.root.name == name || self.edges.iter().any(|(_, child, _)| child.name == name)
        }

        fn dev_dependencies(&self) -> impl Iterator<Item = &Package> {
            self.edges
                .iter()
                .filter(|(parent, _, dev)| *dev && *parent == self.root)
                .map(|(_, child, _)| child)
        }
    }

    /// Why collection produced no list. Reported through telemetry as a fixed code, since the
    /// details (cargo's output, paths on the build machine) must not leave the build.
    #[derive(Clone, Copy)]
    enum Failure {
        WorkspaceNotFound,
        CargoUnavailable,
        CargoMetadataFailed,
        CargoTreeFailed,
    }

    impl Failure {
        fn code(self) -> &'static str {
            match self {
                Failure::WorkspaceNotFound => "workspace_not_found",
                Failure::CargoUnavailable => "cargo_unavailable",
                Failure::CargoMetadataFailed => "cargo_metadata_failed",
                Failure::CargoTreeFailed => "cargo_tree_failed",
            }
        }
    }

    /// A failure and its details, which are only shown in the build output.
    type Error = (Failure, String);

    /// Runs cargo against the application's workspace.
    struct Cargo {
        path: OsString,
        workspace: PathBuf,
        target: String,
    }

    impl Cargo {
        /// Runs cargo with `args`, attributing a non-zero exit to `failure`.
        fn run(&self, args: &[&str], failure: Failure) -> Result<String, Error> {
            let output = Command::new(&self.path)
                .args(args)
                .current_dir(&self.workspace)
                // Don't recurse into rustc wrappers such as `cargo auditable`.
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
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
        println!("cargo::rerun-if-env-changed={ENABLED_ENV}");
        println!("cargo::rerun-if-env-changed={WORKSPACE_DIR_ENV}");

        let recorded = match collection_enabled().then(collect) {
            None => Recorded::default(),
            Some(Ok(graph)) => Recorded::with(graph),
            Some(Err((failure, details))) => {
                println!(
                    "cargo::warning=dependency collection failed ({}): {details}",
                    failure.code()
                );
                Recorded::with_error(failure.code())
            }
        };

        let out_dir = env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
        let written = fs::write(
            Path::new(&out_dir).join("build_time_dependencies.rs"),
            render(&recorded),
        );
        // The tracer only includes the file when this cfg is set, and builds that don't run this
        // script don't set it, so a missing file never fails the build.
        println!("cargo::rustc-check-cfg=cfg({RECORDED_CFG})");
        match written {
            Ok(()) => println!("cargo::rustc-cfg={RECORDED_CFG}"),
            Err(err) => {
                println!("cargo::warning=dependency collection failed ({WRITE_FAILED}): {err}");
                println!("cargo::rustc-env={FAILURE_ENV}={WRITE_FAILED}");
            }
        }
    }

    /// Renders `recorded` as a Rust expression of type `Recorded`.
    fn render(Recorded { graph, failure }: &Recorded) -> String {
        if let Some(failure) = failure {
            return format!("Recorded::with_error({failure:?})\n");
        }
        let packages: String = graph
            .packages
            .iter()
            .map(|Package { name, version }| {
                format!("Package {{ name: {name:?}.into(), version: {version:?}.into() }},\n")
            })
            .collect();
        let dependencies: String = graph
            .dependencies
            .iter()
            .map(|edges| {
                let edges: String = edges
                    .iter()
                    .map(|(package, builds)| format!("({package}, Builds::{builds:?}), "))
                    .collect();
                format!("std::collections::BTreeMap::from([{edges}]),\n")
            })
            .collect();
        let members: String = graph
            .members
            .iter()
            .map(|member| {
                let dev_dependencies = match &member.dev_dependencies {
                    Some(dev) => {
                        let dev: Vec<String> = dev.iter().map(usize::to_string).collect();
                        format!("Some(vec![{}])", dev.join(", "))
                    }
                    None => "None".to_owned(),
                };
                let targets: String = member
                    .targets
                    .iter()
                    .map(|Target { name, kind }| {
                        format!("Target {{ name: {name:?}.into(), kind: TargetKind::{kind:?} }}, ")
                    })
                    .collect();
                format!(
                    "Member {{ package: {}, dev_dependencies: {dev_dependencies}, \
                     targets: vec![{targets}] }},\n",
                    member.package
                )
            })
            .collect();
        format!(
            "Recorded::with(Graph {{\n\
             packages: vec![\n{packages}],\n\
             dependencies: vec![\n{dependencies}],\n\
             members: vec![\n{members}],\n\
             }})\n"
        )
    }

    /// Mirrors the runtime parsing of the flag: only `false` and `0` disable collection.
    fn collection_enabled() -> bool {
        !matches!(env::var(ENABLED_ENV).as_deref(), Ok("false" | "0"))
    }

    fn collect() -> Result<Graph, Error> {
        let unavailable = |details: &str| (Failure::CargoUnavailable, details.to_owned());
        let workspace = workspace_dir().ok_or_else(|| {
            let details = format!(
                "the target directory is not in the workspace root; set {WORKSPACE_DIR_ENV} to it"
            );
            (Failure::WorkspaceNotFound, details)
        })?;
        let cargo = Cargo {
            path: env::var_os("CARGO").ok_or_else(|| unavailable("CARGO is not set"))?,
            workspace,
            target: env::var("TARGET").map_err(|_| unavailable("TARGET is not set"))?,
        };
        println!(
            "cargo::rerun-if-changed={}",
            cargo.workspace.join("Cargo.lock").display()
        );

        let packages = workspace_packages(&cargo)?;
        let mut builder = GraphBuilder::default();
        let mut tree_error = None;
        for package in &packages {
            if let Err(err) = add_member(&cargo, &mut builder, package) {
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
    /// (`--target-dir`, `CARGO_TARGET_DIR`, `build.target-dir`). Rather than guessing, this
    /// returns `None` when that parent holds no `Cargo.lock`.
    fn workspace_dir() -> Option<PathBuf> {
        if let Some(dir) = env::var_os(WORKSPACE_DIR_ENV) {
            return Some(PathBuf::from(dir)).filter(|dir| dir.is_dir());
        }
        let out_dir = PathBuf::from(env::var_os("OUT_DIR")?);
        // Cargo tags the root of the target directory, whatever its layout below.
        let target_dir = out_dir
            .ancestors()
            .find(|dir| dir.join("CACHEDIR.TAG").is_file())?;
        target_dir
            .parent()
            .filter(|dir| dir.join("Cargo.lock").is_file())
            .map(Path::to_path_buf)
    }

    /// The workspace packages, from `cargo metadata --no-deps`, which only reads workspace
    /// manifests and so works offline even when the dependencies of packages that aren't
    /// being built were never downloaded.
    fn workspace_packages(cargo: &Cargo) -> Result<Vec<Value>, Error> {
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

    /// Adds a workspace `package` to the graph if it depends on this crate, normally or
    /// through its dev-dependencies.
    fn add_member(cargo: &Cargo, builder: &mut GraphBuilder, package: &Value) -> Result<(), Error> {
        if let Some(manifest) = package["manifest_path"].as_str() {
            println!("cargo::rerun-if-changed={manifest}");
        }
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
        let targets = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(target)
            .collect();
        builder.graph.members.push(Member {
            package: root,
            dev_dependencies,
            targets,
        });
        Ok(())
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
    fn dependency_tree(cargo: &Cargo, id: &str, edges: &str) -> Result<Tree, Error> {
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

    /// Parses `cargo tree --prefix indent --charset ascii --format {p}` output. Each level is
    /// indented by four characters, and a `[dev-dependencies]` line, indented like the
    /// package it belongs to, starts that package's dev section.
    fn parse_tree(output: &str) -> Option<Tree> {
        let mut lines = output.lines();
        let root = parse_package(lines.next()?)?;
        // The packages on the path to the current line, and whether their children seen
        // next are dev-dependencies.
        let mut path = vec![(root.clone(), false)];
        let mut edges = Vec::new();
        for line in lines {
            let text = line.trim_start_matches(['|', '`', '-', ' ']);
            let depth = (line.len() - text.len()) / 4;
            if text.starts_with('[') {
                if let Some((_, dev)) = path.get_mut(depth) {
                    *dev = text == "[dev-dependencies]";
                }
                continue;
            }
            let Some(package) = parse_package(text) else {
                continue;
            };
            path.truncate(depth);
            let Some((parent, dev)) = path.last() else {
                continue;
            };
            edges.push((parent.clone(), package.clone(), *dev));
            path.push((package, false));
        }
        Some(Tree { root, edges })
    }

    /// Parses a `cargo tree --format {p}` entry: `name vX.Y.Z [(source)] [(proc-macro)] [(*)]`.
    fn parse_package(text: &str) -> Option<Package> {
        let mut fields = text.split_whitespace();
        let name = fields.next()?;
        let version = fields.next()?.strip_prefix('v')?;
        Some(Package {
            name: name.to_owned(),
            version: version.to_owned(),
        })
    }
}

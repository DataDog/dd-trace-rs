// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Records the runtime dependencies of the application being built.
//!
//! With the `dependency-collection` feature, this script locates the workspace being built
//! (the application's, not this crate's), lists its binary targets with
//! `cargo metadata --no-deps` and resolves the runtime dependencies of each workspace package
//! that depends on this crate with `cargo tree`. The result is written to
//! `$OUT_DIR/dependencies.rs` and reported through telemetry at runtime.
//!
//! Collection is best-effort: any failure yields an empty list and never fails the build.
//! Instead, the failure is recorded as a fixed code that the tracer reports as a telemetry
//! error at runtime. Setting `DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED=false` at build time skips
//! collection, and is not reported as a failure.

fn main() {
    #[cfg(feature = "dependency-collection")]
    dependencies::generate();
}

#[cfg(feature = "dependency-collection")]
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

    const ENABLED_ENV: &str = "DD_TELEMETRY_DEPENDENCY_COLLECTION_ENABLED";
    const WORKSPACE_DIR_ENV: &str = "CARGO_WORKSPACE_DIR";

    /// A `(name, version)` pair.
    type Package = (String, String);

    /// A binary target of the application's workspace and its runtime dependencies.
    struct Binary {
        name: String,
        dependencies: BTreeSet<Package>,
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

        let result = if collection_enabled() {
            collect()
        } else {
            Ok(Vec::new())
        };
        if let Err((failure, details)) = &result {
            println!(
                "cargo::warning=dependency collection failed ({}): {details}",
                failure.code()
            );
        }

        let out_dir = env::var_os("OUT_DIR").expect("cargo sets OUT_DIR for build scripts");
        fs::write(Path::new(&out_dir).join("dependencies.rs"), render(&result))
            .expect("failed to write the dependency list to OUT_DIR");
    }

    /// Mirrors the runtime parsing of the flag: only `false` and `0` disable collection.
    fn collection_enabled() -> bool {
        !matches!(env::var(ENABLED_ENV).as_deref(), Ok("false" | "0"))
    }

    fn collect() -> Result<Vec<Binary>, Error> {
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
        let mut binaries = Vec::new();
        let mut tree_error = None;
        for package in &packages {
            match package_binaries(&cargo, package) {
                Ok(found) => binaries.extend(found),
                Err(err) => tree_error = Some(err),
            }
        }
        // Some packages failing is expected when building a single package of a workspace:
        // the dependencies of the others may never have been downloaded.
        if !binaries.is_empty() {
            return Ok(binaries);
        }
        if let Some(err) = tree_error {
            return Err(err);
        }
        // Not a failure: e.g. a `cdylib` application has no binary target.
        println!("cargo::warning=no binary target of the workspace depends on this crate");
        Ok(binaries)
    }

    /// The root of the workspace being built, as `esp-idf-sys` (`embuild`) locates it:
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

    /// The binary targets of a workspace `package`, or none if it doesn't depend on this crate.
    fn package_binaries(cargo: &Cargo, package: &Value) -> Result<Vec<Binary>, Error> {
        if let Some(manifest) = package["manifest_path"].as_str() {
            println!("cargo::rerun-if-changed={manifest}");
        }
        let names: Vec<&str> = package["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|target| is_bin(target))
            .filter_map(|target| target["name"].as_str())
            .collect();
        let Some(id) = package["id"].as_str().filter(|_| !names.is_empty()) else {
            return Ok(Vec::new());
        };
        let Some(dependencies) = runtime_dependencies(cargo, id)? else {
            return Ok(Vec::new());
        };
        Ok(names
            .into_iter()
            .map(|name| Binary {
                name: name.to_owned(),
                dependencies: dependencies.clone(),
            })
            .collect())
    }

    fn is_bin(target: &Value) -> bool {
        target["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
    }

    /// The runtime dependencies of the package `id` for the current target: normal edges
    /// only, proc-macros excluded. `None` if they don't include this crate.
    fn runtime_dependencies(cargo: &Cargo, id: &str) -> Result<Option<BTreeSet<Package>>, Error> {
        let args = [
            "tree",
            "--offline",
            "--locked",
            "--edges",
            "normal,no-proc-macro",
            "--prefix",
            "none",
            "--format",
            "{p}",
            "--target",
            &cargo.target,
            "--package",
            id,
        ];
        let tree = cargo
            .run(&args, Failure::CargoTreeFailed)
            .inspect_err(|(_, details)| println!("cargo::warning=skipping {id}: {details}"))?;
        // The first line is the package itself.
        let dependencies: BTreeSet<Package> =
            tree.lines().skip(1).filter_map(parse_tree_line).collect();
        Ok(dependencies
            .iter()
            .any(|(name, _)| name == env!("CARGO_PKG_NAME"))
            .then_some(dependencies))
    }

    /// Parses a `cargo tree --format {p}` line: `name vX.Y.Z [(source)] [(*)]`.
    fn parse_tree_line(line: &str) -> Option<Package> {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let version = fields.next()?.strip_prefix('v')?;
        Some((name.to_owned(), version.to_owned()))
    }

    /// Renders the `BINARIES` and `FAILURE` statics read by `core/telemetry/dependencies.rs`.
    fn render(result: &Result<Vec<Binary>, Error>) -> String {
        let (binaries, failure) = match result {
            Ok(binaries) => (binaries.as_slice(), "None".to_owned()),
            Err((failure, _)) => ([].as_slice(), format!("Some({:?})", failure.code())),
        };
        let entries: String = binaries
            .iter()
            .map(|binary| {
                let packages: String = binary
                    .dependencies
                    .iter()
                    .map(|(name, version)| format!("({name:?}, {version:?}), "))
                    .collect();
                format!("    ({:?}, &[{packages}]),\n", binary.name)
            })
            .collect();
        format!(
            "static BINARIES: &[Binary] = &[\n{entries}];\n\
             static FAILURE: Option<&str> = {failure};\n"
        )
    }
}

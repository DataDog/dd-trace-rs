// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Locates the workspace from the build output directory, and turns `cargo tree` output into the
//! graph `build.rs` records.
//!
//! The build script compiles this file too (through `#[path]`), so it must only use `std`. The
//! tracer only compiles it for its tests.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use super::graph::{Builds, Graph, Package};

/// The workspace root of a build script whose `OUT_DIR` is `out_dir`: its nearest ancestor
/// holding a `Cargo.lock`, which cargo only writes at workspace roots, so whatever the layout of
/// the target directory below it, e.g. with `--target`.
///
/// The target directory's `CACHEDIR.TAG` isn't a reliable marker: cargo only writes it when it
/// creates the directory, not when it already exists, e.g. restored from a cache.
pub fn workspace_root(out_dir: &Path) -> Option<PathBuf> {
    out_dir
        .ancestors()
        .find(|dir| dir.join("Cargo.lock").is_file())
        .map(Path::to_path_buf)
}

/// A package as cargo identifies it: packages with the same name and version can come from
/// different sources, e.g. crates.io and a patched git checkout, and depend on different
/// packages.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Node {
    pub package: Package,
    /// As `cargo tree` shows it, which it doesn't for crates.io.
    pub source: Option<String>,
}

#[derive(Default)]
pub struct GraphBuilder {
    pub graph: Graph,
    index: HashMap<Node, usize>,
}

impl GraphBuilder {
    pub fn node(&mut self, node: &Node) -> usize {
        if let Some(&index) = self.index.get(node) {
            return index;
        }
        let graph = &mut self.graph;
        graph.packages.push(node.package.clone());
        graph.dependencies.push(BTreeMap::new());
        self.index.insert(node.clone(), graph.packages.len() - 1);
        graph.packages.len() - 1
    }

    /// Adds the non-dev edges of `tree`, seen in `builds`, and returns its root.
    pub fn add_tree(&mut self, tree: &Tree, builds: Builds) -> usize {
        for edge in tree.edges.iter().filter(|edge| !edge.dev) {
            let (parent, child) = (self.node(&edge.parent), self.node(&edge.child));
            self.graph.dependencies[parent]
                .entry(child)
                .and_modify(|seen| *seen = seen.merge(builds))
                .or_insert(builds);
        }
        self.node(&tree.root)
    }
}

pub struct Tree {
    pub root: Node,
    pub edges: Vec<Edge>,
}

#[derive(Debug, PartialEq)]
pub struct Edge {
    pub parent: Node,
    pub child: Node,
    /// Whether `child` is a dev-dependency of `parent`.
    pub dev: bool,
}

impl Tree {
    pub fn contains(&self, name: &str) -> bool {
        let is = |node: &Node| node.package.name == name;
        is(&self.root) || self.edges.iter().any(|edge| is(&edge.child))
    }

    pub fn dev_dependencies(&self) -> impl Iterator<Item = &Node> {
        self.edges
            .iter()
            .filter(|edge| edge.dev && edge.parent == self.root)
            .map(|edge| &edge.child)
    }
}

/// Parses `cargo tree --prefix indent --charset ascii --format {p}` output. Each level is
/// indented by four characters, and a `[dev-dependencies]` line, indented like the
/// package it belongs to, starts that package's dev section.
pub fn parse_tree(output: &str) -> Option<Tree> {
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
        edges.push(Edge {
            parent: parent.clone(),
            child: package.clone(),
            dev: *dev,
        });
        path.push((package, false));
    }
    Some(Tree { root, edges })
}

/// The names of the packages in `cargo tree --prefix none --format {p}` output.
pub fn package_names(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(parse_package)
        .map(|node| node.package.name)
        .collect()
}

/// Parses a `cargo tree --format {p}` entry: `name vX.Y.Z [(source)] [(proc-macro)] [(*)]`.
fn parse_package(text: &str) -> Option<Node> {
    let (name, rest) = text.split_once(' ')?;
    let (version, rest) = rest.split_once(' ').unwrap_or((rest, ""));
    let version = version.strip_prefix('v')?;
    let rest = rest.trim();
    let rest = rest.strip_suffix("(*)").unwrap_or(rest).trim_end();
    let source = rest.strip_suffix("(proc-macro)").unwrap_or(rest).trim_end();
    Some(Node {
        package: Package {
            name: name.to_owned(),
            version: version.to_owned(),
        },
        source: (!source.is_empty()).then(|| source.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn node(name: &str, version: &str, source: Option<&str>) -> Node {
        Node {
            package: Package {
                name: name.to_owned(),
                version: version.to_owned(),
            },
            source: source.map(str::to_owned),
        }
    }

    /// Target directories laid out as cargo does, without the `CACHEDIR.TAG` it doesn't write in
    /// one that already existed: `ws/target`, `ws/build/target` in the workspace `ws`, and
    /// `elsewhere/target` outside any workspace.
    #[test]
    fn test_workspace_root() {
        let root = std::env::temp_dir().join(format!("dd-workspace-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let ws = root.join("ws");
        fs::create_dir_all(&ws).expect("create the workspace");
        fs::write(ws.join("Cargo.lock"), "").expect("write the lockfile");
        let out_dir = |target: &Path, profile: &str| {
            let dir = target.join(profile).join("build/app-0123456789abcdef/out");
            fs::create_dir_all(&dir).expect("create OUT_DIR");
            dir
        };
        let target = ws.join("target");

        assert_eq!(workspace_root(&out_dir(&target, "debug")), Some(ws.clone()));
        // `--target`
        assert_eq!(
            workspace_root(&out_dir(&target, "x86_64-unknown-linux-musl/release")),
            Some(ws.clone())
        );
        // `CARGO_TARGET_DIR=build/target`
        assert_eq!(
            workspace_root(&out_dir(&ws.join("build/target"), "debug")),
            Some(ws.clone())
        );
        // Moved out of the workspace, e.g. by `cross`.
        assert_eq!(
            workspace_root(&out_dir(&root.join("elsewhere/target"), "debug")),
            None
        );

        fs::remove_dir_all(&root).expect("remove the test directory");
    }

    fn edge(parent: &Node, child: &Node, dev: bool) -> Edge {
        Edge {
            parent: parent.clone(),
            child: child.clone(),
            dev,
        }
    }

    fn tree(output: &str) -> Tree {
        parse_tree(output).expect("the output parses")
    }

    #[test]
    fn test_parse_package() {
        let parse = |text| parse_package(text).expect("the entry parses");
        assert_eq!(parse("itoa v1.0.15"), node("itoa", "1.0.15", None));
        assert_eq!(parse("itoa v1.0.15 (*)"), node("itoa", "1.0.15", None));
        assert_eq!(
            parse("serde_derive v1.0.219 (proc-macro)"),
            node("serde_derive", "1.0.219", None)
        );
        assert_eq!(
            parse("serde_derive v1.0.219 (proc-macro) (*)"),
            node("serde_derive", "1.0.219", None)
        );
        assert_eq!(
            parse("app v0.1.0 (/work/app)"),
            node("app", "0.1.0", Some("(/work/app)"))
        );
        assert_eq!(
            parse("itoa v1.0.15 (https://github.com/dtolnay/itoa#a1b2c3d4) (*)"),
            node(
                "itoa",
                "1.0.15",
                Some("(https://github.com/dtolnay/itoa#a1b2c3d4)")
            )
        );
        assert_eq!(
            parse("derive v0.2.0 (/work/derive) (proc-macro) (*)"),
            node("derive", "0.2.0", Some("(/work/derive)"))
        );
        assert_eq!(parse_package("[dev-dependencies]"), None);
        assert_eq!(parse_package("itoa 1.0.15"), None);
        assert_eq!(parse_package(""), None);
    }

    #[test]
    fn test_parse_tree() {
        let tree = tree(
            "app v0.1.0 (/work/app)\n\
             |-- itoa v1.0.15\n\
             |-- serde v1.0.219\n\
             |   `-- serde_derive v1.0.219 (proc-macro)\n\
             |       `-- itoa v1.0.15 (*)\n\
             `-- lib v0.1.0 (/work/lib)\n\
             \x20   `-- itoa v1.0.15 (*)\n",
        );
        let app = node("app", "0.1.0", Some("(/work/app)"));
        let itoa = node("itoa", "1.0.15", None);
        let serde = node("serde", "1.0.219", None);
        let serde_derive = node("serde_derive", "1.0.219", None);
        let lib = node("lib", "0.1.0", Some("(/work/lib)"));
        assert_eq!(tree.root, app);
        assert_eq!(
            tree.edges,
            vec![
                edge(&app, &itoa, false),
                edge(&app, &serde, false),
                edge(&serde, &serde_derive, false),
                edge(&serde_derive, &itoa, false),
                edge(&app, &lib, false),
                edge(&lib, &itoa, false),
            ]
        );
        assert!(tree.contains("app"));
        assert!(tree.contains("serde_derive"));
        assert!(!tree.contains("anyhow"));
        assert_eq!(tree.dev_dependencies().count(), 0);
    }

    #[test]
    fn test_parse_tree_dev_dependencies() {
        let tree = tree(
            "app v0.1.0 (/work/app)\n\
             `-- lib v0.1.0 (/work/lib)\n\
             \x20   |-- itoa v1.0.15\n\
             \x20   [dev-dependencies]\n\
             \x20   `-- anyhow v1.0.98\n\
             [dev-dependencies]\n\
             |-- tempfile v3.20.0\n\
             |   `-- itoa v1.0.15 (*)\n\
             `-- lib v0.1.0 (/work/lib) (*)\n",
        );
        let app = node("app", "0.1.0", Some("(/work/app)"));
        let lib = node("lib", "0.1.0", Some("(/work/lib)"));
        let itoa = node("itoa", "1.0.15", None);
        let anyhow = node("anyhow", "1.0.98", None);
        let tempfile = node("tempfile", "3.20.0", None);
        assert_eq!(
            tree.edges,
            vec![
                edge(&app, &lib, false),
                edge(&lib, &itoa, false),
                edge(&lib, &anyhow, true),
                edge(&app, &tempfile, true),
                edge(&tempfile, &itoa, false),
                edge(&app, &lib, true),
            ]
        );
        let dev: Vec<&Node> = tree.dev_dependencies().collect();
        assert_eq!(dev, vec![&tempfile, &lib]);
    }

    #[test]
    fn test_package_names() {
        // An inverted tree: this crate, then the packages that depend on it.
        let names = package_names(
            "datadog-opentelemetry v0.5.3\n\
             lib v0.1.0 (/work/lib)\n\
             app v0.1.0 (/work/app)\n\
             lib v0.1.0 (/work/lib) (*)\n\
             \n\
             tests v0.1.0 (/work/tests)\n",
        );
        let expected = ["app", "datadog-opentelemetry", "lib", "tests"];
        assert_eq!(names, BTreeSet::from(expected.map(str::to_owned)));
    }

    #[test]
    fn test_parse_tree_without_root() {
        assert!(parse_tree("").is_none());
        assert!(parse_tree("error: package not found\n").is_none());
    }

    #[test]
    fn test_graph_builder_keeps_sources_apart() {
        // The same name and version, from crates.io and a git checkout that adds a dependency.
        let mut builder = GraphBuilder::default();
        let app = builder.add_tree(
            &tree(
                "app v0.1.0 (/work/app)\n\
                 `-- itoa v1.0.15\n",
            ),
            Builds::Both,
        );
        let worker = builder.add_tree(
            &tree(
                "worker v0.1.0 (/work/worker)\n\
                 `-- itoa v1.0.15 (https://github.com/dtolnay/itoa#a1b2c3d4)\n\
                 \x20   `-- extra v0.1.0\n",
            ),
            Builds::Both,
        );
        let graph = &builder.graph;
        let index = |name: &str| -> Vec<usize> {
            (0..graph.packages.len())
                .filter(|&i| graph.packages[i].name == name)
                .collect()
        };
        let (itoa, extra) = (index("itoa"), index("extra"));
        assert_eq!(itoa.len(), 2);
        assert_eq!(extra.len(), 1);
        let deps = |package: usize| -> Vec<usize> {
            graph.dependencies[package].keys().copied().collect()
        };
        let app_itoa = deps(app);
        let worker_itoa = deps(worker);
        assert_eq!(app_itoa.len(), 1);
        assert_eq!(worker_itoa.len(), 1);
        assert_ne!(app_itoa, worker_itoa);
        assert!(deps(app_itoa[0]).is_empty());
        assert_eq!(deps(worker_itoa[0]), extra);
    }

    #[test]
    fn test_graph_builder_merges_builds() {
        let mut builder = GraphBuilder::default();
        let output = "app v0.1.0 (/work/app)\n\
                      |-- itoa v1.0.15\n\
                      [dev-dependencies]\n\
                      `-- anyhow v1.0.98\n";
        let root = builder.add_tree(
            &tree("app v0.1.0 (/work/app)\n`-- itoa v1.0.15\n"),
            Builds::Bin,
        );
        assert_eq!(builder.add_tree(&tree(output), Builds::Test), root);
        let graph = &builder.graph;
        // Dev edges aren't added: the dev-dependencies are recorded per member.
        assert_eq!(graph.packages.len(), 2);
        assert_eq!(
            graph.dependencies[root]
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![Builds::Both]
        );
        assert_eq!(builder.node(&node("itoa", "1.0.15", None)), 1);
    }
}

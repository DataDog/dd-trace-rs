// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Turns `cargo tree` output into the graph `build.rs` records, and renders it as the Rust
//! expression the tracer includes.
//!
//! The build script compiles this file too (through `#[path]`), so it must only use `std`. The
//! tracer only compiles it for its tests.

use std::collections::{BTreeMap, HashMap};

use super::graph::{Builds, Graph, Package, Recorded, Target};

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

pub struct Tree {
    pub root: Node,
    /// `(parent, child, is a dev-dependency)`.
    pub edges: Vec<(Node, Node, bool)>,
}

impl Tree {
    pub fn contains(&self, name: &str) -> bool {
        let is = |node: &Node| node.package.name == name;
        is(&self.root) || self.edges.iter().any(|(_, child, _)| is(child))
    }

    pub fn dev_dependencies(&self) -> impl Iterator<Item = &Node> {
        self.edges
            .iter()
            .filter(|(parent, _, dev)| *dev && *parent == self.root)
            .map(|(_, child, _)| child)
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
        edges.push((parent.clone(), package.clone(), *dev));
        path.push((package, false));
    }
    Some(Tree { root, edges })
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

pub fn render(Recorded { graph, failure }: &Recorded) -> String {
    if let Some(failure) = failure {
        return format!("Recorded::with_error(Failure::{failure:?})\n");
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
            format!(
                "Member {{ package: {}, dev_dependencies: {dev_dependencies}, \
                 targets: vec![{}] }},\n",
                member.package,
                render_targets(&member.targets)
            )
        })
        .collect();
    let unresolved = render_targets(&graph.unresolved);
    format!(
        "Recorded::with(Graph {{\n\
         packages: vec![\n{packages}],\n\
         dependencies: vec![\n{dependencies}],\n\
         members: vec![\n{members}],\n\
         unresolved: vec![{unresolved}],\n\
         }})\n"
    )
}

fn render_targets(targets: &[Target]) -> String {
    targets
        .iter()
        .map(|Target { name, kind }| {
            format!("Target {{ name: {name:?}.into(), kind: TargetKind::{kind:?} }}, ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::graph::{Failure, Member, TargetKind};
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
                (app.clone(), itoa.clone(), false),
                (app.clone(), serde.clone(), false),
                (serde, serde_derive.clone(), false),
                (serde_derive, itoa.clone(), false),
                (app, lib.clone(), false),
                (lib, itoa, false),
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
                (app.clone(), lib.clone(), false),
                (lib.clone(), itoa.clone(), false),
                (lib.clone(), anyhow, true),
                (app.clone(), tempfile.clone(), true),
                (tempfile.clone(), itoa, false),
                (app, lib.clone(), true),
            ]
        );
        let dev: Vec<&Node> = tree.dev_dependencies().collect();
        assert_eq!(dev, vec![&tempfile, &lib]);
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

    #[test]
    fn test_render() {
        let mut builder = GraphBuilder::default();
        let root = builder.add_tree(
            &tree("app v0.1.0 (/work/app)\n`-- itoa v1.0.15\n"),
            Builds::Bin,
        );
        let graph = &mut builder.graph;
        graph.members.push(Member {
            package: root,
            dev_dependencies: Some(vec![1]),
            targets: vec![Target {
                name: "app".to_owned(),
                kind: TargetKind::Bin,
            }],
        });
        graph.members.push(Member {
            package: root,
            dev_dependencies: None,
            targets: Vec::new(),
        });
        graph.unresolved.push(Target {
            name: "worker".to_owned(),
            kind: TargetKind::Other,
        });
        let recorded = Recorded::with(std::mem::take(&mut builder.graph));
        assert_eq!(
            render(&recorded),
            "Recorded::with(Graph {\n\
             packages: vec![\n\
             Package { name: \"app\".into(), version: \"0.1.0\".into() },\n\
             Package { name: \"itoa\".into(), version: \"1.0.15\".into() },\n\
             ],\n\
             dependencies: vec![\n\
             std::collections::BTreeMap::from([(1, Builds::Bin), ]),\n\
             std::collections::BTreeMap::from([]),\n\
             ],\n\
             members: vec![\n\
             Member { package: 0, dev_dependencies: Some(vec![1]), \
             targets: vec![Target { name: \"app\".into(), kind: TargetKind::Bin }, ] },\n\
             Member { package: 0, dev_dependencies: None, targets: vec![] },\n\
             ],\n\
             unresolved: vec![Target { name: \"worker\".into(), kind: TargetKind::Other }, ],\n\
             })\n"
        );
        assert_eq!(
            render(&Recorded::with_error(Failure::CargoTreeFailed)),
            "Recorded::with_error(Failure::CargoTreeFailed)\n"
        );
    }
}

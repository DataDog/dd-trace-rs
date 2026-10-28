// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The dependency graph `build.rs` records and the tracer reads at runtime.
//!
//! The build script compiles this file too (through `#[path]`), so it must only use `std`.

use std::collections::BTreeMap;

#[derive(Default)]
pub struct Recorded {
    pub graph: Graph,
    pub failure: Option<String>,
}

impl Recorded {
    #[allow(dead_code)]
    pub fn with(graph: Graph) -> Self {
        Self {
            graph,
            failure: None,
        }
    }

    #[allow(dead_code)]
    pub fn with_error(failure: &str) -> Self {
        Self {
            graph: Graph::default(),
            failure: Some(failure.to_owned()),
        }
    }
}

#[derive(Default)]
pub struct Graph {
    pub packages: Vec<Package>,
    pub dependencies: Vec<BTreeMap<usize, Builds>>,
    pub members: Vec<Member>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builds {
    Bin,
    Test,
    Both,
}

impl Builds {
    // allow: only the build script merges builds
    #[allow(dead_code)]
    pub fn merge(self, other: Self) -> Self {
        if self == other {
            self
        } else {
            Self::Both
        }
    }

    // allow: only the tracer checks builds
    #[allow(dead_code)]
    pub fn includes(self, build: Self) -> bool {
        self == Self::Both || self == build
    }
}

pub struct Member {
    pub package: usize,
    /// `None` if the dev-dependencies couldn't be resolved, e.g. weren't downloaded.
    pub dev_dependencies: Option<Vec<usize>>,
    pub targets: Vec<Target>,
}

pub struct Target {
    pub name: String,
    pub kind: TargetKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Bin,
    Example,
    /// Libraries, tests and benches: only run as test harnesses.
    // allow: the tracer only constructs it from a non-empty recorded graph
    #[allow(dead_code)]
    Other,
}

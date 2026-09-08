// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // The `_unstable_propagation` feature used to gate the propagation module.
    // Propagation is now always available (via the `datadog-trace-propagation`
    // crate), so the feature no longer has any effect.
    // Reading CARGO_FEATURE_* variables in a build script is the only way to
    // detect enabled features, so the env-access lint is deliberately allowed here.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE__UNSTABLE_PROPAGATION");
    #[allow(clippy::disallowed_methods)]
    {
        if std::env::var_os("CARGO_FEATURE__UNSTABLE_PROPAGATION").is_some() {
            println!(
                "cargo:warning=The `_unstable_propagation` feature of datadog-opentelemetry is deprecated and has no effect: trace context propagation is now always available via the `datadog-trace-propagation` crate."
            );
        }
    }
}

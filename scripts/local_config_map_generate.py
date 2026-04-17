import json
import subprocess

supported_configurations_file = open("supported-configurations.json", "r")
supported_configurations = json.load(supported_configurations_file)

# PLEASE DO NOT ADD ANYTHING TO THIS LIST.
# Only reason this exists is to test the code with fake env vars.
undocumented_configurations = {
    "DD_COMPLEX_STRUCT": {
        "aliases": [],
        "deprecated": False,
    },
    "DD_NONEXISTANT_CONFIGURATION": {
        "aliases": [
            "DD_NONEXISTANT_CONFIGURATION_ALIAS",
            "DD_NONEXISTANT_CONFIGURATION_DEPRECATED_ALIAS",
        ],
        "deprecated": False,
    },
    "DD_NONEXISTANT_CONFIGURATION_ALIAS": {
        "aliases": [],
        "deprecated": False,
    },
    "DD_NONEXISTANT_CONFIGURATION_DEPRECATED": {
        "aliases": [],
        "deprecated": True,
    },
}

# JSON type → Rust type
TYPE_MAP = {
    "string": "Cow<'static, str>",
    "int": "u32",
    "decimal": "f64",
    "boolean": "bool",
    "map": "Vec<(String, String)>",
    "array": "Option<Vec<TracePropagationStyle>>",
}

# ── Build blocks from JSON ───────────────────────────────────────────────────

enum_block = ""
as_str_block = ""
aliases_block = []
alias_deprecated_block = []
deprecated_block = []
struct_field_lines = []
getter_lines = []
setter_lines = []
telemetry_lines = []
debug_lines = []
default_config_lines = []

for i, (key, versions) in enumerate(
    supported_configurations["supportedConfigurations"].items()
):
    if i != 0:
        enum_block += "\n"
        as_str_block += "\n"

    enum_block += "    {},".format(key)
    as_str_block += '            SupportedConfigurations::{} => "{}",'.format(key, key)

    json_type = versions[0]["type"]
    default_val = versions[0].get("default")
    property_keys = versions[0].get("propertyKeys", [])
    field_name = property_keys[0] if property_keys else None
    skip_raw = versions[0].get("skip_default_generation", "")
    if skip_raw is True or skip_raw == "all":
        skip_set = {"getter", "setter", "default"}
    elif skip_raw:
        skip_set = {s.strip() for s in skip_raw.split(",")}
    else:
        skip_set = set()

    # Build struct field line
    if field_name:
        rust_type = versions[0].get("rust_type", TYPE_MAP.get(json_type))
        config_item_type = versions[0].get("config_item_type")
        if config_item_type in ("override_code", "override_rc"):
            struct_field_lines.append(
                "    pub(super) {}: ConfigItemWithOverride<{}>,".format(field_name, rust_type)
            )
        else:
            struct_field_lines.append(
                "    pub(super) {}: ConfigItem<{}>,".format(field_name, rust_type)
            )

    # Build doc comment shared by getter and setter
    default_display = versions[0].get("default")
    all_aliases = [a for v in versions for a in v.get("aliases", [])]

    def getter_doc():
        return "    /// Returns the value of `{}`.".format(key)

    def setter_doc():
        lines = ["    /// Sets the value of `{}`.".format(key)]
        if default_display is not None:
            lines += ["    ///", "    ///  **Default**: `{}`".format(default_display), "    ///"]
        lines.append("    /// Env variable: `{}`".format(key))
        if all_aliases:
            lines.append("    /// Aliases: {}".format(", ".join("`{}`".format(a) for a in all_aliases)))
        return "\n".join(lines)

    # Build getter/setter lines for simple types
    skip_getters = "getter" in skip_set
    skip_setters = "setter" in skip_set
    if field_name and json_type in ("string", "int", "decimal", "boolean"):
        if json_type == "string":
            if not skip_getters:
                getter_lines.append(
                    "{}\n    pub fn {}(&self) -> &str {{ self.{}.value().as_ref() }}".format(
                        getter_doc(), field_name, field_name
                    )
                )
            if not skip_setters:
                setter_lines.append(
                    "{}\n    pub fn set_{}(&mut self, val: String) -> &mut Self {{ self.config.{}.set_code(Cow::Owned(val)); self }}".format(
                        setter_doc(), field_name, field_name
                    )
                )
        elif json_type == "int":
            if not skip_getters:
                getter_lines.append(
                    "{}\n    pub fn {}(&self) -> u32 {{ *self.{}.value() }}".format(
                        getter_doc(), field_name, field_name
                    )
                )
            if not skip_setters:
                setter_lines.append(
                    "{}\n    pub fn set_{}(&mut self, val: u32) -> &mut Self {{ self.config.{}.set_code(val); self }}".format(
                        setter_doc(), field_name, field_name
                    )
                )
        elif json_type == "decimal":
            if not skip_getters:
                getter_lines.append(
                    "{}\n    pub fn {}(&self) -> f64 {{ *self.{}.value() }}".format(
                        getter_doc(), field_name, field_name
                    )
                )
            if not skip_setters:
                setter_lines.append(
                    "{}\n    pub fn set_{}(&mut self, val: f64) -> &mut Self {{ self.config.{}.set_code(val); self }}".format(
                        setter_doc(), field_name, field_name
                    )
                )
        elif json_type == "boolean":
            if not skip_getters:
                getter_lines.append(
                    "{}\n    pub fn {}(&self) -> bool {{ *self.{}.value() }}".format(
                        getter_doc(), field_name, field_name
                    )
                )
            if not skip_setters:
                setter_lines.append(
                    "{}\n    pub fn set_{}(&mut self, val: bool) -> &mut Self {{ self.config.{}.set_code(val); self }}".format(
                        setter_doc(), field_name, field_name
                    )
                )

    # Build default_config() field line
    if field_name:
        rust_value = versions[0].get("rust_value")
        config_item_type = versions[0].get("config_item_type")
        if rust_value is not None:
            if config_item_type == "override_code":
                default_config_lines.append(
                    "        {}: ConfigItemWithOverride::new_code(S::{}, {}),".format(
                        field_name, key, rust_value
                    )
                )
            elif config_item_type == "override_rc":
                default_config_lines.append(
                    "        {}: ConfigItemWithOverride::new_rc(S::{}, {}),".format(
                        field_name, key, rust_value
                    )
                )
            else:
                default_config_lines.append(
                    "        {}: ConfigItem::new(S::{}, {}),".format(
                        field_name, key, rust_value
                    )
                )
        elif "default" not in skip_set:
            rust_val = None
            if json_type == "string":
                rust_val = 'Cow::Borrowed("{}")'.format(default_val or "")
            elif json_type == "int":
                rust_val = str(int(default_val)) if default_val is not None else "0"
            elif json_type == "decimal":
                rust_val = str(float(default_val)) if default_val is not None else "0.0"
            elif json_type == "boolean":
                rust_val = ("true" if default_val == "true" else "false") if default_val is not None else "false"
            elif json_type == "map":
                rust_val = "Vec::new()"
            if rust_val is not None:
                default_config_lines.append(
                    "        {}: ConfigItem::new(S::{}, {}),".format(field_name, key, rust_val)
                )

    # Build telemetry config and Debug lines for ALL configs with propertyKeys
    if field_name:
        telemetry_lines.append("            &self.{},".format(field_name))
        debug_lines.append(
            '            .field("{}", &self.{})'.format(field_name, field_name)
        )

    # Aliases and deprecation
    aliases_accumulator = []
    for version in versions:
        if "aliases" in version:
            for alias in version["aliases"]:
                aliases_accumulator.append(alias)
                if alias not in supported_configurations["supportedConfigurations"]:
                    alias_deprecated_block.append('"{}" => true,'.format(alias))
        if "deprecated" in version and version["deprecated"]:
            deprecated_block.append(
                "SupportedConfigurations::{} => true,".format(key)
            )
    if aliases_accumulator:
        quoted = ", ".join('"{}"'.format(a) for a in aliases_accumulator)
        aliases_block.append(
            "SupportedConfigurations::{} => &[{}],".format(key, quoted)
        )

# Undocumented test configurations
if undocumented_configurations:
    enum_block += "\n\n    /// Used for testing purposes only"
for key in undocumented_configurations:
    conf = undocumented_configurations[key]
    enum_block += "\n    #[cfg(test)]\n    #[allow(unused)]\n    {},".format(key)
    as_str_block += '\n            #[cfg(test)]\n            SupportedConfigurations::{} => "{}",'.format(
        key, key
    )
    if conf["aliases"]:
        quoted = ", ".join('"{}"'.format(a) for a in conf["aliases"])
        aliases_block.append(
            "#[cfg(test)]\n            SupportedConfigurations::{} => &[{}],".format(
                key, quoted
            )
        )
    if conf["deprecated"]:
        deprecated_block.append(
            "#[cfg(test)]\n            SupportedConfigurations::{} => true,".format(key)
        )
    for alias in conf["aliases"]:
        if alias not in undocumented_configurations:
            alias_deprecated_block.append(
                '#[cfg(test)]\n        "{}" => true,'.format(alias)
            )

# ── Assemble template ────────────────────────────────────────────────────────

NL = "\n            "

result = """\
// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

/// This file is generated by the scripts/local_config_map_generate.py script.
/// Do not edit this file manually. To add a new configuration,
/// add it to the supported-configurations.json file, then run this script.
use std::borrow::Cow;
use std::sync::{{Arc, Mutex}};

use rustc_version_runtime::version;

use super::*;

#[allow(nonstandard_style)]
#[derive(Debug, PartialEq, Copy, Clone)]
#[non_exhaustive]
pub enum SupportedConfigurations {{
{enum_block}
}}

impl SupportedConfigurations {{
    pub fn as_str(&self) -> &'static str {{
        match self {{
{as_str_block}
        }}
    }}

    pub fn aliases(&self) -> &[&'static str] {{
        match self {{
            {aliases_joined}
            _ => &[],
        }}
    }}

    pub fn is_deprecated(&self) -> bool {{
        match self {{
            {deprecated_joined}
            _ => false,
        }}
    }}
}}

pub fn is_alias_deprecated(name: &str) -> bool {{
    match name {{
        {alias_deprecated_joined}
        _ => false,
    }}
}}

/// Configuration for the Datadog Tracer
///
/// # Usage
/// ```
/// use datadog_opentelemetry::configuration::Config;
///
///
/// let config = Config::builder() // This pulls configuration from the environment and other sources
///     .set_service("my-service".to_string()) // Override service name
///     .set_version("1.0.0".to_string()) // Override version
/// .build();
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct Config {{
    pub(super) runtime_id: &'static str,
    pub(super) tracer_version: &'static str,
    pub(super) language_version: String,
    pub(super) language: &'static str,
{struct_fields_block}
    #[cfg(feature = "test-utils")]
    pub(super) wait_agent_info_ready: bool,
    pub(super) extra_services_tracker: ExtraServicesTracker,
    pub(super) remote_config_callbacks: Arc<Mutex<RemoteConfigCallbacks>>,
}}

#[allow(missing_docs)]
impl Config {{
{getters_block}

    pub(crate) fn get_telemetry_configuration(&self) -> Vec<&dyn ConfigurationProvider> {{
        vec![
{telemetry_block}
        ]
    }}
}}

#[allow(missing_docs)]
impl ConfigBuilder {{
{setters_block}
}}

pub(super) fn default_config() -> Config {{
    use SupportedConfigurations as S;
    Config {{
        runtime_id: Config::process_runtime_id(),
        tracer_version: TRACER_VERSION,
        language: "rust",
        language_version: version().to_string(),
        #[cfg(feature = "test-utils")]
        wait_agent_info_ready: false,
        extra_services_tracker: ExtraServicesTracker::new(),
        remote_config_callbacks: Arc::new(Mutex::new(RemoteConfigCallbacks::new())),
{default_config_block}
    }}
}}

impl std::fmt::Debug for Config {{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        f.debug_struct("Config")
            .field("runtime_id", &self.runtime_id)
            .field("tracer_version", &self.tracer_version)
            .field("language_version", &self.language_version)
{debug_block}
            .field("extra_services_tracker", &self.extra_services_tracker)
            .field("remote_config_callbacks", &self.remote_config_callbacks)
            .finish()
    }}
}}
""".format(
    enum_block=enum_block,
    as_str_block=as_str_block,
    aliases_joined=NL.join(aliases_block),
    deprecated_joined=NL.join(deprecated_block),
    alias_deprecated_joined=NL.join(alias_deprecated_block),
    struct_fields_block="\n".join(struct_field_lines),
    default_config_block="\n".join(default_config_lines),
    getters_block="\n\n".join(getter_lines),
    setters_block="\n\n".join(setter_lines),
    telemetry_block="\n".join(telemetry_lines),
    debug_block="\n".join(debug_lines),
)

OUTPUT = "datadog-opentelemetry/src/core/configuration/supported_configurations.rs"
with open(OUTPUT, "w") as f:
    f.write(result)

subprocess.run(["rustfmt", OUTPUT])
print("Done.")

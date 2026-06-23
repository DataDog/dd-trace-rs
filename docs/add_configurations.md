# Adding Configuration Options

## Overview

Configuration options are defined in `supported-configurations.json` at the project root. A Python
script (`scripts/local_config_map_generate.py`) reads this JSON file and generates
`datadog-opentelemetry/src/core/configuration/supported_configurations.rs`. A CI check will ensure
that the files are sorted and synchronized, so don't forget to sort `supported-configurations.json`
and run the `scripts/local_config_map_generate.py` script!

## Prerequisites

- **Python 3.14** — required to run `scripts/local_config_map_generate.py`

## Configuration Schema

Each configuration entry in `supported-configurations.json` follows this structure:

```json
"DD_CONFIG_NAME": [
  {
    "version": "A",
    "type": "string|integer|decimal|boolean|array|map",
    "default": "default value as string",
    "propertyKeys": [
      "internal_property_name"
    ],
    "aliases": [
      "OTEL_ALTERNATE_NAME"
    ],
    "deprecated_aliases": [
      "DD_OLD_NAME"
    ],
    "deprecated": true | false
  }
]
```

### Fields

- **version**: The implementation version of the configuration (available on the FPD). If there is a
  difference with an existing one, it is a different version and you must create a new one on the
  FPD.
- **type**: Data type - one of: `string`, `integer`, `decimal`, `boolean`, `array`, or `map`. For
  now, it is only informative.
- **default**: Default value as a string (even for non-string types). Also currently only
  informative.
- **propertyKeys**: Array containing the internal property name(s) used in the configuration struct.
  Also currently only informative.
- **aliases** (optional): Array of alternative environment variable names that are accepted without
  a deprecation warning (e.g. standard OpenTelemetry env vars like `OTEL_SERVICE_NAME`)
- **deprecated_aliases** (optional): Array of old environment variable names that still work but
  emit a deprecation warning at runtime, directing users to the canonical name
- **deprecated** (optional): Boolean indicating if this configuration is deprecated

## Adding a New Configuration

1. **Edit `supported-configurations.json`**
   - Add your new configuration entry in alphabetical order (KEEP THE KEYS SORTED!)
   - Ensure proper JSON formatting

Example:

```json
"DD_MY_NEW_CONFIG": [
  {
    "version": "A",
    "type": "string",
    "default": "my-default",
    "propertyKeys": [
      "my_new_config"
    ]
  }
]
```

2. **Run the generation script**

From the project root, run:

```bash
python3 scripts/local_config_map_generate.py
```

This will:

- Read `supported-configurations.json`
- Generate `datadog-opentelemetry/src/core/configuration/supported_configurations.rs`
- Automatically format the generated Rust code using `rustfmt`

3. **Implement the configuration usage**

After generation, you need to implement the actual configuration logic in your code, typically in
`datadog-opentelemetry/src/core/configuration/configuration.rs`

## Working with Aliases and Deprecation

### Alias Types

There are two kinds of aliases in `supported-configurations.json`:

- **`aliases`** — accepted without a deprecation warning. Use for Datadog-specific alternative
  names that are in the FPD registry as aliases of the canonical key.
- **`deprecated_aliases`** — accepted but emit a deprecation warning at runtime, directing the
  user to the canonical name. Use when renaming an existing Datadog env var.

**Note:** For standard names from other ecosystems (e.g. OpenTelemetry env vars), do **not** use
the `aliases` field. Register them as separate top-level entries and handle the fallback in code.
See [Adding a Standard Alternative Name](#adding-a-standard-alternative-name-eg-opentelemetry).

### Deprecating a Configuration with Replacement

If you want to rename an existing Datadog env var:

1. Create a new configuration with the replacement name
2. Delete the original configuration entry
3. Add the original name to the **`deprecated_aliases`** array in the replacement config

Example:

```json
"DD_NEW_CONFIG_NAME": [
  {
    "version": "A",
    "type": "string",
    "default": "value",
    "propertyKeys": [
      "config_property"
    ],
    "deprecated_aliases": [
      "DD_OLD_CONFIG_NAME"
    ]
  }
]
```

### Adding a Standard Alternative Name (e.g. OpenTelemetry)

If a standard name from another ecosystem (e.g. OpenTelemetry) should be accepted alongside the
Datadog name, register it as a **separate top-level entry** in `supported-configurations.json` —
this matches how other Datadog tracers (Python, Go, Java) register it and satisfies the Feature
Parity Dashboard (FPD) validation. Then handle the fallback in code.

For example, `OTEL_SERVICE_NAME` is registered as its own entry:

```json
"OTEL_SERVICE_NAME": [
  {
    "version": "B",
    "type": "string",
    "default": null,
    "propertyKeys": []
  }
]
```

And the precedence (`DD_SERVICE` wins; `OTEL_SERVICE_NAME` used when `DD_SERVICE` is absent) is
implemented explicitly in `configuration.rs` — not via the `aliases` field. This is because the
FPD validates that local `aliases` are a subset of aliases registered in the FPD, and the FPD
treats OTel env vars as separate configs, not as aliases of their DD counterparts.

### Deprecating a Configuration Without Replacement

To deprecate a configuration without providing a replacement:

1. Keep the configuration entry
2. Set `"deprecated": true`

```json
"DD_OLD_CONFIG": [
  {
    "version": "A",
    "type": "string",
    "default": "",
    "propertyKeys": [
      "old_property"
    ],
    "deprecated": true
  }
]
```

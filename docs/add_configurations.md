# Adding Configuration Options

## Overview

Configuration options are defined in `supported-configurations.json` at the project root. A Python script (`scripts/local_config_map_generate.py`) reads this JSON file and generates `datadog-opentelemetry/src/core/configuration/supported_configurations.rs`. A CI check will ensure that the files are sorted and synchronized, so don't forget to sort `supported-configurations.json` and run the `scripts/local_config_map_generate.py` script!

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
      "DD_ALTERNATE_NAME"
    ],
    "deprecated": true | false
  }
]
```

### Fields

- **version**: The implementation version of the configuration (available on the FPD). If there is a difference with an existing one, it is a different version and you must create a new one on the FPD.
- **type**: Data type - one of: `string`, `integer`, `decimal`, `boolean`, `array`, or `map`. For now, it is only informative.
- **default**: Default value as a string (even for non-string types). Also currently only informative.
- **propertyKeys**: Array containing the internal property name(s) used in the configuration struct. Also currently only informative.
- **aliases** (optional): Array of alternative environment variable names
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

After generation, you need to implement the actual configuration logic in your code, typically in `datadog-opentelemetry/src/core/configuration/configuration.rs`

## Working with Aliases and Deprecation

### Basic Alias Rules

- **When an alias isn't registered as its own config key, it is by default deprecated.**
- The script automatically detects unregistered aliases and marks them as deprecated in the generated code.

### Deprecating a Configuration with Replacement

If you want to deprecate a config and provide a replacement:

1. Create a new configuration with the replacement name
2. Delete the original configuration entry
3. Add the original name to the `aliases` array in the replacement config

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
    "aliases": [
      "DD_OLD_CONFIG_NAME"
    ]
  }
]
```

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

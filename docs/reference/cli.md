# CLI Reference

The `runner` command executes plugins against commits stored in Neo4j.

## Installation

```bash
poetry install
```

## Usage

```bash
poetry run runner [OPTIONS] COMMIT_HASH PLUGIN_TYPE
```

Or if installed:

```bash
runner [OPTIONS] COMMIT_HASH PLUGIN_TYPE
```

## Arguments

### COMMIT_HASH

The hash of the commit to process. Must exist in the Neo4j database.

### PLUGIN_TYPE

The plugin to execute. Case-insensitive.

**Available plugins:**

| Plugin Type | Description |
|-------------|-------------|
| `filetype` | Detects MIME types for all files |
| `symbols` | Extracts PDB symbols from PE files |
| `winreg` | Parses Windows Registry hives |

## Options

### `--debug` / `-d`

Enable debug logging output.

```bash
poetry run runner -d abc123 filetype
```

## Examples

### Run FileType plugin

```bash
poetry run runner abc123def456 filetype
```

### Run Windows Registry plugin with debug output

```bash
poetry run runner -d abc123def456 winreg
```

### Run Symbols plugin

```bash
poetry run runner abc123def456 symbols
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Unknown plugin type or unregistered plugin |

## Environment

The runner uses Dynaconf for configuration with the environment variable prefix `GPLUGINS`.

See `plugins/config/default_settings.toml` for default configuration values.

## Plugin Execution Order

Some plugins have dependencies:

1. **FileTypePlugin** - No dependencies, can run first
2. **SymbolsPlugin** - Requires FileTypePlugin to identify PE files
3. **WinRegistryPlugin** - No dependencies

Recommended execution order:

```bash
poetry run runner <hash> filetype
poetry run runner <hash> winreg
poetry run runner <hash> symbols
```

## Debugging

The runner includes a post-mortem debugger. If an unhandled exception occurs, it will drop into `ipdb` for inspection:

```python
# In __main__.py
@post_mortem
def runner(debug, commit_hash, plugin_type_str):
    ...
```

To use the debugger, ensure `ipdb` is installed (included in dev dependencies).

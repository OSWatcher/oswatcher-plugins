# GraphEOS Plugins Documentation

GraphEOS Plugins is a framework for analyzing filesystem snapshots stored in Neo4j via [neogit](https://github.com/OSWatcher/neogit). It provides plugins that extract and store domain-specific information (MIME types, Windows registry data, debug symbols) as graph nodes.

## Quick Links

| I want to... | Go to |
|--------------|-------|
| Run my first plugin | [Getting Started](tutorials/getting-started.md) |
| Query plugin results | [Query Data](how-to/query-data.md) |
| Create a new plugin | [Create Plugin](how-to/create-plugin.md) |
| Understand the data model | [Data Model Reference](reference/data-model.md) |

---

## Documentation Structure

This documentation follows the [Divio documentation system](https://documentation.divio.com/).

### Tutorials

Learning-oriented guides for getting started.

- [Getting Started](tutorials/getting-started.md) - Run your first plugin

### How-To Guides

Task-oriented guides for specific goals.

- [Create a Plugin](how-to/create-plugin.md) - Build a new analysis plugin
- [Query Data](how-to/query-data.md) - Cypher queries for plugin data

### Reference

Technical specifications and API documentation.

- [Data Model](reference/data-model.md) - Complete Neo4j schema
- [Plugin API](reference/plugin-api.md) - AbstractPlugin class reference
- [CLI Reference](reference/cli.md) - Command-line interface

### Explanation

Conceptual discussions of architecture and design.

- [Architecture](explanation/architecture.md) - System design overview
- [Merkle Pattern](explanation/merkle-pattern.md) - Content-addressed storage
- [Symbols Plugin](explanation/symbols-plugin.md) - Deep dive into PDB symbol extraction

---

## Available Plugins

| Plugin | Description | Data Created |
|--------|-------------|--------------|
| `filetype` | Detects file MIME types | `MimeType` nodes |
| `winreg` | Parses Windows registry | `WinRegKey`, `WinRegValue` nodes |
| `symbols` | Extracts PDB debug symbols | `Symbol`, `WinStruct`, `WinStructField` nodes |

---

## Installation

```bash
poetry install
```

## Basic Usage

```bash
# Run a plugin
poetry run runner <commit_hash> <plugin_type>

# Example
poetry run runner abc123 filetype
```

See [CLI Reference](reference/cli.md) for full details.

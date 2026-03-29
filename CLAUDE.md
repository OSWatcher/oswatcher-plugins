# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Grapheos Plugins is a plugin framework for processing and analyzing data from Git commits stored in a Neo4j graph database via the `neogit` library. Plugins analyze filesystem artifacts (Windows registry hives, PE files, etc.) and store structured results as graph nodes and relationships.

## Development Commands

```bash
# Install dependencies
poetry install

# Format code
poetry run poe fmt

# Lint (flake8 + isort)
poetry run poe lint

# Type checking
poetry run poe typing

# Format + lint combined
poetry run poe ccode

# Run a plugin
poetry run runner <commit_hash> <plugin_type>
# Example: poetry run runner abc123 filetype
```

## Architecture

### Plugin System

- **Entry point**: `plugins/__main__.py` - CLI runner using Click that loads a commit from Neo4j and executes a plugin
- **Base class**: `plugins/types.py:AbstractPlugin` - Abstract base class all plugins inherit from. Provides:
  - Neo4j database access via `self.neogit`
  - Constraint creation (`ensure_constraints()`)
  - File download helper (`downloaded_file()` context manager)
  - Transaction management and plugin run tracking
- **Plugin registry**: `plugins/plugins/__init__.py` - `PluginType` enum and `MAP_PLUGIN` dictionary mapping types to plugin classes

### Available Plugins

All plugins are in `plugins/plugins/`:

1. **FileTypePlugin** (`filetype.py`) - Identifies MIME types of blobs using libmagic
2. **WinRegistryPlugin** (`registry.py`) - Parses Windows registry hives (SAM, SECURITY, SOFTWARE, SYSTEM, BCD) and stores keys/values as graph nodes
3. **SymbolsPlugin** (`symbols.py`) - Extracts PDB debug symbols from PE files (ntoskrnl.exe, ntdll.dll, kernel32.dll, win32kfull.sys, win32kbase.sys, win32k.sys) and stores structs/symbols

### Merkle Tree Pattern

Plugins use a Merkle tree visitor pattern from `neogit` for content-addressed storage:
- `MerkleVisitor` base class traverses node trees
- Each node type has a corresponding `MerkleNode` subclass
- Hashes are computed from node content, enabling deduplication

### Configuration

- Uses Dynaconf for settings (`plugins/config/__init__.py`)
- Environment variable prefix: `GPLUGINS`
- Settings file: `plugins/config/default_settings.toml`

## Key Dependencies

- `neogit`: Neo4j graph database ORM and Merkle tree utilities
- `lief`: PE file parsing
- `volatility3`: PDB symbol extraction
- `regipy`: Windows registry hive parsing
- `python-magic`: MIME type detection
- `attrs`: Data class definitions

## Documentation

Full documentation is available in `docs/`:

- [Data Model Reference](docs/reference/data-model.md) - Neo4j schema for all plugins
- [Plugin API Reference](docs/reference/plugin-api.md) - AbstractPlugin class API
- [Architecture](docs/explanation/architecture.md) - System design overview
- [How to Create a Plugin](docs/how-to/create-plugin.md) - Plugin development guide

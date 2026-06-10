# OSWatcher Plugins

Analysis plugins for [OSWatcher](https://github.com/OSWatcher) — extract and analyze operating system artifacts (filesystem, registry, PDB symbols, syscalls) and store them as a queryable graph in Neo4j.

## Installation

```bash
pip install oswatcher-plugins
```

## Plugins

| Plugin | Description |
|--------|-------------|
| `FileTypePlugin` | Identifies file types within OS filesystem snapshots |
| `SymbolsPlugin` | Extracts PDB symbols and struct layouts from PE binaries |
| `WinRegistryPlugin` | Parses and inserts Windows registry hives |
| `SyscallsPlugin` | Extracts Windows/Linux syscall tables |
| `LinuxSymbolsPlugin` | Extracts Linux kernel debug symbols |

## Usage

Plugins are run via the `runner` CLI against a [neogit](https://github.com/OSWatcher/neogit) branch:

```bash
runner <plugin_name> <branch_name>
# example:
runner symbols Windows_10_21H2
```

## Requirements

- Python 3.11+
- A running Neo4j instance (configured via `neogit` settings)
- [neogit](https://github.com/OSWatcher/neogit) — the underlying graph storage library

## Documentation

- [Syscall Data Model Specification](docs/syscall-data-model.md)
- [Neo4j Insertion Pattern](docs/neo4j-insertion-pattern.md)

## License

Apache 2.0 — see [LICENSE](LICENSE).

# Getting Started

This tutorial walks through running your first plugin on a commit.

## Prerequisites

- Neo4j database running with neogit data
- A commit hash from your neogit repository

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd grapheos-plugins

# Install dependencies
poetry install
```

## Running a Plugin

### Step 1: Identify a Commit

Get a commit hash from your Neo4j database:

```cypher
MATCH (c:Commit)
RETURN c.hash, c.name
LIMIT 5
```

### Step 2: Run FileTypePlugin

The FileTypePlugin identifies MIME types for all files:

```bash
poetry run runner <commit_hash> filetype
```

Example:

```bash
poetry run runner abc123def456 filetype
```

Expected output:

```
INFO:plugins.plugins.filetype.FileTypePlugin:root: Tree(hash='xyz789')
INFO:plugins.plugins.filetype.FileTypePlugin:[0] blob: abc123 - application/octet-stream
INFO:plugins.plugins.filetype.FileTypePlugin:[1] blob: def456 - text/plain
...
```

### Step 3: Verify Results

Check the data in Neo4j:

```cypher
// Count MIME types discovered
MATCH (m:MimeType)
RETURN m.mime, count { ()-[:HAS_MIME_TYPE]->(m) } AS count
ORDER BY count DESC

// Verify plugin run recorded
MATCH (c:Commit {hash: $commit_hash})-[:HAS_PLUGIN_RUN]->(pr:PluginRun)
RETURN pr.filetype
```

## Running Additional Plugins

### Windows Registry Plugin

Parses Windows registry hives:

```bash
poetry run runner <commit_hash> winreg
```

Verify:

```cypher
// List registry hives found
MATCH (b:Blob)-[r:HAS_WINREG]->(k:WinRegKey)
RETURN r.name AS hive
```

### Symbols Plugin

Extracts debug symbols from PE files. Requires FileTypePlugin first:

```bash
# Run filetype first (if not already)
poetry run runner <commit_hash> filetype

# Then symbols
poetry run runner <commit_hash> symbols
```

Verify:

```cypher
// List structs found
MATCH (b:Blob)-[r:HAS_STRUCT]->(s:WinStruct)
RETURN r.name AS struct, s.size
LIMIT 20
```

## Debug Mode

Enable verbose logging with `-d`:

```bash
poetry run runner -d <commit_hash> filetype
```

## Re-running Plugins

Plugins track their execution time. Running the same plugin on the same commit will skip:

```
INFO:Plugin run node already executed at 2024-01-15 10:30:00 for commit abc123
```

To re-run, delete the PluginRun relationship:

```cypher
MATCH (c:Commit {hash: $commit_hash})-[:HAS_PLUGIN_RUN]->(pr:PluginRun)
SET pr.filetype = null  // Reset specific plugin
// Or: DETACH DELETE pr  // Reset all plugins
```

## Next Steps

- [Query Plugin Data](../how-to/query-data.md) - Learn to query results
- [Create a Plugin](../how-to/create-plugin.md) - Build your own plugin
- [Data Model Reference](../reference/data-model.md) - Understand the data structure

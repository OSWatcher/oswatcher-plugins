# How to Create a New Plugin

This guide walks through creating a new plugin for OSWatcher Plugins.

## Step 1: Create the Plugin File

Create a new file in `plugins/plugins/`:

```python
# plugins/plugins/myplugin.py

from typing import List

from attrs import define
from neogit.model.neo import Commit

from plugins.types import AbstractPlugin, UniqueConstraint


@define(auto_attribs=True)
class MyPlugin(AbstractPlugin):

    def constraints_data(self) -> List[UniqueConstraint]:
        """Define unique constraints for your nodes."""
        return [
            UniqueConstraint(label="MyNode", property_list=["hash"]),
        ]

    def run(self, commit: Commit):
        """Main plugin logic."""
        # Get filesystem root
        fs = commit.filesystem.single()

        # Process files
        for path, blob in fs.all_blobs():
            self.process_file(path, blob)

    def process_file(self, path, blob):
        """Process a single file."""
        self.logger.info("Processing: %s", path)

        # Download file content
        with self.downloaded_file(blob.hash) as local_path:
            # Analyze the file
            result = self.analyze(local_path)

        # Store result in Neo4j
        self.store_result(blob.hash, result)

    def analyze(self, local_path):
        """Perform analysis on file."""
        # Your analysis logic here
        return {"hash": "computed_hash", "data": "analysis_result"}

    def store_result(self, blob_hash, result):
        """Store analysis result in Neo4j."""
        query = """
        MERGE (n:MyNode {hash: $hash})
        SET n.data = $data
        WITH n
        MATCH (b:Blob {hash: $blob_hash})
        MERGE (b)-[:HAS_ANALYSIS]->(n)
        """
        self.neogit.db.cypher_query(query, {
            "hash": result["hash"],
            "data": result["data"],
            "blob_hash": blob_hash,
        })
```

## Step 2: Register the Plugin

Edit `plugins/plugins/__init__.py`:

```python
from enum import Enum, auto
from typing import Dict, Type

from plugins.types import AbstractPlugin

from .filetype import FileTypePlugin
from .myplugin import MyPlugin  # Add import
from .registry import WinRegistryPlugin
from .symbols import SymbolsPlugin


class PluginType(Enum):
    FILETYPE = auto()
    MYPLUGIN = auto()  # Add enum value
    SYMBOLS = auto()
    WINREG = auto()


MAP_PLUGIN: Dict[PluginType, Type[AbstractPlugin]] = {
    PluginType.FILETYPE: FileTypePlugin,
    PluginType.MYPLUGIN: MyPlugin,  # Add mapping
    PluginType.SYMBOLS: SymbolsPlugin,
    PluginType.WINREG: WinRegistryPlugin,
}

__all__ = ["MAP_PLUGIN", "PluginType", "MyPlugin", "SymbolsPlugin", "WinRegistryPlugin"]
```

## Step 3: Run the Plugin

```bash
poetry run runner <commit_hash> myplugin
```

## Common Patterns

### Filter Files by Path

```python
def run(self, commit: Commit):
    fs = commit.filesystem.single()

    for path, blob in fs.all_blobs():
        # Only process specific files
        if path.suffix == ".exe":
            self.process_file(path, blob)
```

### Filter Files by MIME Type

Requires FileTypePlugin to run first:

```python
def run(self, commit: Commit):
    fs = commit.filesystem.single()

    query = """
    MATCH (r:Tree {hash: $root_hash})-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
    MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType)
    WHERE m.mime = $mime_type
    RETURN b.hash
    """
    rows, _ = self.neogit.db.cypher_query(query, {
        "root_hash": fs.hash,
        "mime_type": "application/pdf"
    })

    for row in rows:
        blob_hash = row[0]
        self.process_blob(blob_hash)
```

### Get File at Specific Path

```python
from pathlib import PurePath

def run(self, commit: Commit):
    fs = commit.filesystem.single()

    try:
        blob = fs.get_blob_at_path(PurePath("/path/to/file.txt"))
        self.process_file(blob)
    except FileNotFoundError:
        self.logger.warning("File not found")
```

### Use Retry for Deadlocks

For high-concurrency scenarios:

```python
from neogit.service.neogit import cypher_query_with_backoff

def store_result(self, result):
    query = "MERGE (n:MyNode {hash: $hash})"
    cypher_query_with_backoff(query, {"hash": result["hash"]})
```

### Use Merkle Hashing

For hierarchical data with deduplication:

```python
import hashlib
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleNode, MerkleLabel, Node
from neogit.core.visitor import VisitedNode


class MyNode(Node):
    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.children = []

    def iter_child_nodes(self):
        return iter(self.children)


class MyMerkleVisitor(MerkleVisitor):
    def visit_MyNode(self, node, hash_obj):
        children = {}

        for child in node.iter_child_nodes():
            visited = self.visit(child)
            merkle = visited.return_value
            hash_obj.update(f"{child.name}{merkle.hash}".encode())
            children[child.name] = merkle

        hash_obj.update(node.data.encode())

        return VisitedNode(node, MerkleNode(
            hash=hash_obj.hexdigest(),
            label=MerkleLabel.Tree,
            children=children
        ))
```

### Parallel Processing

For CPU-intensive tasks:

```python
import pypeln as pl

def run(self, commit: Commit):
    fs = commit.filesystem.single()
    blobs = ((path, blob) for path, blob in fs.all_blobs())

    # Process in parallel
    stage = pl.process.map(self.process_blob, blobs, workers=4)

    for result in stage:
        if isinstance(result, Exception):
            self.logger.error("Error: %s", result)
            continue
        self.store_result(result)
```

## Testing Your Plugin

### Manual Testing

```bash
# Enable debug output
poetry run runner -d <commit_hash> myplugin
```

### Verify in Neo4j

```cypher
// Check nodes were created
MATCH (n:MyNode) RETURN count(n)

// Check relationships
MATCH (b:Blob)-[:HAS_ANALYSIS]->(n:MyNode)
RETURN b.hash, n.hash LIMIT 10

// Check constraint exists
SHOW CONSTRAINTS
```

## Checklist

- [ ] Plugin class inherits from `AbstractPlugin`
- [ ] `constraints_data()` defines unique constraints
- [ ] `run()` implements main logic
- [ ] Plugin registered in `PluginType` enum
- [ ] Plugin mapped in `MAP_PLUGIN` dictionary
- [ ] Plugin imported in `__init__.py`
- [ ] Cypher queries use MERGE for idempotency
- [ ] Logging used for progress/errors

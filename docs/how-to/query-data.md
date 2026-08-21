# How to Query Plugin Data

This guide provides Cypher query examples for accessing data created by OSWatcher Plugins.

## Base Model Queries

### List All Commits

```cypher
MATCH (c:Commit)
RETURN c.hash, c.name, c.date
ORDER BY c.date DESC
```

### Get Commit History

```cypher
MATCH path = (c:Commit {hash: $commit_hash})-[:HAS_PREVIOUS*]->(ancestor:Commit)
RETURN [node IN nodes(path) | node.hash] AS history
```

### Browse Filesystem

```cypher
// Get root tree
MATCH (c:Commit {hash: $commit_hash})-[:OWNS_FILESYSTEM]->(root:Tree)
RETURN root.hash

// List directory contents
MATCH (t:Tree {hash: $tree_hash})-[r:HAS_CHILD_TREE|HAS_CHILD_BLOB]->(child)
RETURN r.name, labels(child)[0] AS type, child.hash
ORDER BY type DESC, r.name
```

### Find File by Path

```cypher
MATCH (c:Commit {hash: $commit_hash})-[:OWNS_FILESYSTEM]->(root:Tree)
MATCH path = (root)-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(target)
WHERE [rel IN relationships(path) | rel.name] = $path_parts
RETURN target.hash
```

Example with path `/Windows/System32/ntoskrnl.exe`:
```cypher
MATCH (c:Commit {hash: "abc123"})-[:OWNS_FILESYSTEM]->(root:Tree)
MATCH path = (root)-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(target)
WHERE [rel IN relationships(path) | rel.name] = ["Windows", "System32", "ntoskrnl.exe"]
RETURN target.hash
```

---

## FileTypePlugin Queries

### List All MIME Types

```cypher
MATCH (m:MimeType)
RETURN m.mime, count { (b:Blob)-[:HAS_MIME_TYPE]->(m) } AS file_count
ORDER BY file_count DESC
```

### Find Files by MIME Type

```cypher
MATCH (b:Blob)-[:HAS_MIME_TYPE]->(m:MimeType {mime: "application/pdf"})
RETURN b.hash
```

### Find Files by MIME Type with Path

```cypher
MATCH (c:Commit {hash: $commit_hash})-[:OWNS_FILESYSTEM]->(root:Tree)
MATCH path = (root)-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType {mime: $mime_type})
RETURN [rel IN relationships(path) | rel.name] AS file_path, b.hash
```

### Count Files by Type in Commit

```cypher
MATCH (c:Commit {hash: $commit_hash})-[:OWNS_FILESYSTEM]->(root:Tree)
MATCH (root)-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType)
RETURN m.mime, count(b) AS count
ORDER BY count DESC
```

---

## WinRegistryPlugin Queries

### List Registry Hives

```cypher
MATCH (b:Blob)-[r:HAS_WINREG]->(k:WinRegKey)
RETURN r.name AS hive_name, k.hash
```

### Browse Registry Key

```cypher
// Get immediate children of a key
MATCH (k:WinRegKey {hash: $key_hash})-[r:HAS_CHILD]->(child)
RETURN r.name, labels(child)[0] AS type,
       CASE WHEN child:WinRegValue THEN child.value ELSE null END AS value,
       CASE WHEN child:WinRegValue THEN child.type ELSE null END AS value_type
ORDER BY type DESC, r.name
```

### Find Registry Key by Path

```cypher
// Find HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
MATCH (b:Blob)-[:HAS_WINREG {name: "SOFTWARE"}]->(root:WinRegKey)
MATCH path = (root)-[:HAS_CHILD*]->(target:WinRegKey)
WHERE [rel IN relationships(path) | rel.name] = ["Microsoft", "Windows", "CurrentVersion"]
RETURN target.hash
```

### Search Registry Values

```cypher
// Find values containing specific text
MATCH (v:WinRegValue)
WHERE v.value CONTAINS $search_term
MATCH (k:WinRegKey)-[r:HAS_CHILD]->(v)
RETURN r.name AS value_name, v.value, v.type, k.hash AS parent_key
```

### Get Full Key Path

```cypher
MATCH (target:WinRegKey {hash: $key_hash})
MATCH path = (root:WinRegKey)-[:HAS_CHILD*0..]->(target)
WHERE NOT ()-[:HAS_CHILD]->(root)  // root has no parent
RETURN [rel IN relationships(path) | rel.name] AS key_path
```

### Compare Registry Between Commits

```cypher
MATCH (c1:Commit {hash: $commit1})-[:OWNS_FILESYSTEM]->()-[:HAS_CHILD_BLOB*]->(b1:Blob)
MATCH (c2:Commit {hash: $commit2})-[:OWNS_FILESYSTEM]->()-[:HAS_CHILD_BLOB*]->(b2:Blob)
MATCH (b1)-[:HAS_WINREG {name: "SOFTWARE"}]->(k1:WinRegKey)
MATCH (b2)-[:HAS_WINREG {name: "SOFTWARE"}]->(k2:WinRegKey)
WHERE k1.hash <> k2.hash
RETURN "SOFTWARE hive changed" AS result
```

---

## SymbolsPlugin Queries

### List Symbols in PE File

```cypher
MATCH (b:Blob {hash: $blob_hash})-[r:HAS_SYMBOL]->(s:Symbol)
RETURN r.name AS symbol_name, s.address
ORDER BY r.name
```

### Search Symbols by Name

```cypher
MATCH (b:Blob)-[r:HAS_SYMBOL]->(s:Symbol)
WHERE r.name CONTAINS $search_term
RETURN r.name AS symbol_name, s.address, b.hash AS pe_file
```

### List Structs in PE File

```cypher
MATCH (b:Blob {hash: $blob_hash})-[r:HAS_STRUCT]->(s:Struct)
RETURN r.name AS struct_name, s.size, s.kind
ORDER BY r.name
```

### Get Struct Definition

```cypher
MATCH (s:Struct {hash: $struct_hash})-[r:HAS_FIELD]->(f:StructField)
RETURN r.name AS field_name, f.offset, f.data_type
ORDER BY f.offset
```

### Find Struct by Name

```cypher
MATCH (b:Blob)-[r:HAS_STRUCT]->(s:Struct)
WHERE r.name = "_EPROCESS"
RETURN b.hash AS pe_file, s.hash, s.size
```

### Compare Struct Across Versions

```cypher
// Find all versions of _EPROCESS
MATCH (b:Blob)-[r:HAS_STRUCT {name: "_EPROCESS"}]->(s:Struct)
RETURN DISTINCT s.hash, s.size
ORDER BY s.size
```

### Get Struct Fields with Types

```cypher
MATCH (s:Struct)-[r:HAS_FIELD]->(f:StructField)
WHERE s.hash = $struct_hash
RETURN r.name AS name, f.offset, f.data_type
ORDER BY f.offset
```

---

## Cross-Plugin Queries

### Find PE Files with Specific Symbol

```cypher
MATCH (b:Blob)-[:HAS_SYMBOL {name: "NtCreateFile"}]->(s:Symbol)
MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType)
RETURN b.hash, m.mime, s.address
```

### Correlate File Types with Registry

```cypher
// Find registry values pointing to executable files
MATCH (v:WinRegValue)
WHERE v.value ENDS WITH ".exe"
MATCH (c:Commit)-[:OWNS_FILESYSTEM]->(root:Tree)
MATCH (root)-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType {mime: "application/vnd.microsoft.portable-executable"})
WHERE v.value CONTAINS b.hash  // simplified; real matching would use path
RETURN v.value, b.hash
```

### Full System Analysis

```cypher
// Get overview of a commit
MATCH (c:Commit {hash: $commit_hash})
OPTIONAL MATCH (c)-[:HAS_PLUGIN_RUN]->(pr:PluginRun)
RETURN c.hash, c.name, c.date,
       pr.filetype AS filetype_run,
       pr.winreg AS winreg_run,
       pr.symbols AS symbols_run
```

---

## Performance Tips

### Use Indexes

Constraints automatically create indexes. Additional indexes can help:

```cypher
CREATE INDEX blob_hash IF NOT EXISTS FOR (b:Blob) ON (b.hash)
CREATE INDEX tree_hash IF NOT EXISTS FOR (t:Tree) ON (t.hash)
```

### Limit Results

```cypher
MATCH (b:Blob)-[:HAS_MIME_TYPE]->(m:MimeType)
RETURN b.hash, m.mime
LIMIT 100
```

### Use Parameters

Always use parameters instead of string interpolation:

```cypher
// Good
MATCH (c:Commit {hash: $commit_hash})

// Bad (security risk, no query caching)
MATCH (c:Commit {hash: "abc123"})
```

### Profile Queries

```cypher
PROFILE
MATCH (b:Blob)-[:HAS_MIME_TYPE]->(m:MimeType)
RETURN count(b)
```

# Neo4j Data Insertion Pattern

## Overview

GraphEOS plugins use a **content-addressed merkle tree visitor pattern** to insert hierarchical data into Neo4j. This architecture is inspired by Git's object model and provides efficient storage with built-in deduplication, tamper detection, and change tracking.

### Three-Layer Architecture

```
Domain Data → Domain Nodes → MerkleVisitor → MerkleNodes → Neo4j
```

1. **Domain Layer**: Parse source data (PDB, registry hives) into tree-structured Node objects
2. **Transformation Layer**: Traverse with MerkleVisitor, computing content hashes bottom-up
3. **Storage Layer**: Insert MerkleNodes into Neo4j using hash-based MERGE queries

## The Three Core Classes

### 1. Node (Base Class)

**Location**: `neogit.core.model.Node`

**Purpose**: Abstract base class representing any traversable domain object with tree structure.

**Key Methods**:
```python
class Node:
    def iter_child_nodes(self) -> Iterator[Node]:
        """Yield child nodes. Default: empty (leaf node)."""
        return iter([])

    def is_leaf(self) -> bool:
        """Check if node has no children."""
        return not any(self.iter_child_nodes())

    def accept(self, visitor) -> Any:
        """Accept a visitor (visitor pattern)."""
        return visitor.visit(self)
```

**Plugin Examples**:
- `WinStructNode`, `WinStructFieldNode` (symbols.py)
- `WinRegKeyNode`, `WinRegValueNode` (registry.py)
- `SyscallTableNode`, `SyscallNode` (syscalls.py - to be implemented)

### 2. MerkleNode (Content-Addressed Node)

**Location**: `neogit.core.model.MerkleNode`

**Purpose**: Extends Node with cryptographic content addressing for tamper-proof storage.

**Key Fields**:
```python
@define(auto_attribs=True)
class MerkleNode(Node):
    hash: str                           # SHA1/256/512 hexdigest (validated)
    label: MerkleLabel                  # Enum: Blob or Tree
    children: Dict[str, MerkleNode]     # Child nodes indexed by name
```

**MerkleLabel Distinction**:
- **`MerkleLabel.Blob`**: Leaf nodes (no children or simple terminal nodes)
- **`MerkleLabel.Tree`**: Internal nodes with children

**Hash Validation**: The hash field is validated to be a proper SHA1/SHA256/SHA512 hexdigest.

### 3. MerkleVisitor (Transformation Engine)

**Location**: `neogit.core.merkle.MerkleVisitor`

**Purpose**: Implements visitor pattern for tree traversal with bottom-up hash computation.

**Key Method**:
```python
class MerkleVisitor(NodeVisitor):
    def visit(self, node: Node, *args, **kwargs):
        """Visit a node, passing a hash object for computation."""
        hash_obj = hashlib.sha1()
        return super().visit(node, hash_obj, *args, **kwargs)

    def visit_SpecificNode(self, node: SpecificNode, hash_obj: hashlib._Hash):
        """Override for each node type to compute its hash."""
        # 1. Visit children
        # 2. Accumulate child hashes
        # 3. Add node-specific data
        # 4. Return VisitedNode(original, MerkleNode(...))
```

### 4. VisitedNode (Wrapper)

**Purpose**: Encapsulates transformation from domain Node to MerkleNode.

```python
@define(auto_attribs=True)
class VisitedNode:
    node: Node                      # Original domain node
    return_value: Optional[Node]    # Resulting MerkleNode
```

**Usage**: Parent nodes access `visited_node.return_value` to get child MerkleNode hashes.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                  VISITOR PATTERN + MERKLE HASHING               │
└─────────────────────────────────────────────────────────────────┘

INPUT LAYER: Domain Nodes (tree structure)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├─ Node (abstract base class)
│  ├─ iter_child_nodes() → Iterator[Node]
│  └─ accept(visitor)
│
├─ WinStructNode (symbols)
│  ├─ name, struct_data, size, kind
│  └─ iter_child_nodes() → WinStructFieldNode[]
│
├─ WinRegKeyNode (registry)
│  ├─ path, key
│  └─ iter_child_nodes() → [WinRegKeyNode, WinRegValueNode]
│
└─ SyscallTableNode (syscalls - future)
   ├─ arch, kernel_version
   └─ iter_child_nodes() → SyscallNode[]

                        ↓

TRANSFORMATION LAYER: Merkle Visitor (bottom-up hash computation)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├─ MerkleVisitor extends NodeVisitor
├─ visit(node) → creates hash_obj, dispatches to visit_SpecificNode()
│
├─ visit_WinStructNode(node, hash_obj):
│  ├─ For each field child:
│  │  ├─ visited = self.visit(field)             # Recursive call
│  │  ├─ merkle_field = visited.return_value     # Get MerkleNode
│  │  └─ hash_obj.update(f"{name}{hash}\n")     # Accumulate
│  ├─ hash_obj.update(f"{size}-{kind}")          # Add metadata
│  └─ Return VisitedNode(node, WinStructMerkleNode(hash, Tree, children))
│
├─ visit_WinRegKeyNode(node, hash_obj):
│  ├─ Sort children (keys first, then values, alphabetically)
│  ├─ For each child: hash_obj.update(f"{name}{hash}\n")
│  └─ Return VisitedNode(node, WinRegKeyMerkleNode(hash, Tree, children))
│
└─ visit_*ValueNode(node, hash_obj):
   ├─ hash_obj.update(value_data)
   └─ Return VisitedNode(node, *ValueMerkleNode(hash, Blob))

                        ↓

OUTPUT LAYER: Merkle Nodes (content-addressed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├─ MerkleNode
│  ├─ hash: str                     # SHA1 hexdigest
│  ├─ label: MerkleLabel            # Blob or Tree
│  ├─ children: Dict[str, MerkleNode]
│  └─ Additional fields (name, size, kind, offset, etc.)
│
├─ Tree nodes: Internal (have children)
│  └─ Examples: WinStructMerkleNode, WinRegKeyMerkleNode
│
└─ Blob nodes: Leaves (no children or terminal)
   └─ Examples: WinStructFieldMerkleNode, WinRegValueMerkleNode

                        ↓

NEO4J INSERTION LAYER: Cypher Queries
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
├─ MERGE nodes by hash (idempotent, deduplicated)
├─ Separate children by label:
│  ├─ Blob children → Create leaf nodes
│  └─ Tree children → Create internal nodes (recurse)
├─ Create relationships with {name: str} property
└─ Connect to filesystem Blob via relationship

                        ↓

                    Neo4j Graph
```

## Data Flow Example: Symbols Plugin

### Step 1: Parse PDB JSON

```python
# symbols.py:349
with self.downloaded_file(blob_hash) as local_file:
    pdb_json = parse_pdb_json(local_file)
    # Result: {"user_types": {"_EPROCESS": {...}, "_FILE_OBJECT": {...}}}
```

### Step 2: Create Domain Nodes

```python
# symbols.py:156-169
@define(auto_attribs=True)
class WinStructNode(Node):
    name: str
    struct_data: Dict
    kind: UserTypeKindType = field(init=False)
    size: int = field(init=False)

    def __attrs_post_init__(self):
        self.kind = UserTypeKindType[self.struct_data["kind"]]
        self.size = self.struct_data["size"]

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        """Yield WinStructFieldNode for each field."""
        for field_name, field_data in self.struct_data.get("fields", {}).items():
            yield WinStructFieldNode(name=field_name, field_data=field_data)
```

### Step 3: Visit with MerkleVisitor

```python
# symbols.py:361-363
with SymbolsMerkleVisitor(thread=True) as visitor:
    for struct_name, struct_data in sorted(j_pdb["user_types"].items()):
        struct_node = WinStructNode(name=struct_name, struct_data=struct_data)
        visitor.run_visit(struct_node)
```

### Step 4: Compute Hash (Bottom-Up)

```python
# symbols.py:228-251
def visit_WinStructNode(self, node: WinStructNode, hash_obj: hashlib._Hash):
    children = {}

    # Visit all field children
    for member in node.iter_child_nodes():
        visited_node = self.visit(member)              # Recursive visit
        merkle_node = visited_node.return_value        # Get MerkleNode result

        # Accumulate field hash into parent
        data = f"{member.name}{merkle_node.hash}\n".encode()
        hash_obj.update(data)

        children[member.name] = merkle_node

    # Add struct metadata to hash
    hash_obj.update(f"{node.size}-{node.kind.name}".encode())

    # Create MerkleNode with computed hash
    merkle_node = WinStructMerkleNode(
        hash=hash_obj.hexdigest(),      # Final hash: fields + metadata
        children=children,               # Dict of field MerkleNodes
        label=MerkleLabel.Tree,          # Internal node (has children)
        name=node.name,
        size=node.size,
        kind=node.kind,
    )
    return VisitedNode(node, merkle_node)
```

**Hash Computation Breakdown**:
```
hash = SHA1(
    "UniqueProcessId" + field1_hash + "\n" +
    "ImageFileName" + field2_hash + "\n" +
    "ActiveProcessLinks" + field3_hash + "\n" +
    ... (all fields) ...
    "1024-struct"                            # size + kind
)
```

### Step 5: Insert into Neo4j

```python
# symbols.py:471-502
def insert_struct_cypher(self, blob_hash: str, node: WinStructMerkleNode):
    # Collect all fields for UNWIND batch operation
    unwind_param = []
    for field_name, field_node in node.children.items():
        if isinstance(field_node, WinStructFieldMerkleNode):
            unwind_param.append({
                "name": field_name,
                "hash": field_node.hash,
                "offset": field_node.offset,
                "data_type": field_node.data_type,
            })

    query = """
    MERGE (s:WinStruct {hash: $hash, size: $size, kind: $kind})
    WITH s
    UNWIND $unwind_param as x
    MERGE (f:WinStructField {hash: x.hash, offset: x.offset, data_type: x.data_type})
    MERGE (s)-[:HAS_FIELD {name: x.name}]->(f)
    WITH s
    MATCH (b:Blob {hash: $blob_hash})
    WITH b, s
    MERGE (b)-[:HAS_STRUCT {name: $name}]->(s)
    """

    cypher_query_with_backoff(query, {
        "hash": node.hash,
        "name": node.name,
        "size": node.size,
        "kind": node.kind.name,
        "unwind_param": unwind_param,
        "blob_hash": blob_hash,
    })
```

**Neo4j Result**:
```
(ntoskrnl.exe:Blob)
    -[:HAS_STRUCT {name: "_EPROCESS"}]->
(struct:WinStruct {hash: "abc123...", size: 1024, kind: "struct"})
    -[:HAS_FIELD {name: "UniqueProcessId"}]->
(field1:WinStructField {hash: "def456...", offset: 0x440, data_type: "void *"})
    -[:HAS_FIELD {name: "ImageFileName"}]->
(field2:WinStructField {hash: "ghi789...", offset: 0x5A8, data_type: "char[15]"})
```

## Data Flow Example: Registry Plugin

### Step 1: Parse Registry Hive

```python
# registry.py:136-142
def dump_hive(hive_path: str, root_name: str) -> WinRegKeyNode:
    reg = Registry.RegistryHive(hive_path)
    root_key = reg.root()
    return WinRegKeyNode(path=PurePath(f"\\{root_name}"), key=root_key)
```

### Step 2: Visit with MerkleVisitor

```python
# registry.py:144-163
with WinRegMerkleVisitor(thread=True) as visitor:
    root_node = dump_hive(hive_path, root_name)
    visitor.run_visit(root_node)

    for visited_node in visitor.as_gen():
        merkle_node = visited_node.return_value
        # Insert recursively
        self.insert_from_visited_node_cypher(merkle_node)
```

### Step 3: Compute Hash (Registry Keys)

```python
# registry.py:107-120
def visit_WinRegKeyNode(self, node: WinRegKeyNode, hash_obj: hashlib._Hash):
    merkle_children = {}

    # Sort children: keys first, then values, alphabetically
    for child_node in sorted(node.iter_child_nodes(),
                            key=lambda e: (not isinstance(e, WinRegKeyNode), e.name)):
        visited_node = self.visit(child_node)
        merkle_node = visited_node.return_value

        # Accumulate child hash
        data = f"{child_node.name}{merkle_node.hash}\n".encode()
        hash_obj.update(data)

        merkle_children[child_node.name] = merkle_node

    merkle_node = WinRegKeyMerkleNode(
        hash=hash_obj.hexdigest(),
        children=merkle_children,
        label=MerkleLabel.Tree,      # Internal node
        key=node.key
    )
    return VisitedNode(node, merkle_node)
```

### Step 4: Insert into Neo4j (Separating Blob/Tree)

```python
# registry.py:170-212
def insert_from_visited_node_cypher(self, node: WinRegKeyMerkleNode):
    # Separate children by label
    child_values = [
        {"name": name, "hash": child.hash, "value": child.value.value,
         "type": child.value.value_type.name}
        for name, child in node.children.items()
        if child.label == MerkleLabel.Blob        # Leaf values
    ]

    child_keys = [
        {"name": name, "hash": child.hash}
        for name, child in node.children.items()
        if child.label == MerkleLabel.Tree        # Internal keys
    ]

    query = """
    MERGE (p:WinRegKey {hash: $parent_hash})
    WITH p
    FOREACH (cv IN $child_values |
        MERGE (v:WinRegValue {hash: cv.hash, value: cv.value, type: cv.type})
        MERGE (p)-[:HAS_CHILD {name: cv.name}]->(v)
    )
    WITH p
    FOREACH (ck IN $child_keys |
        MERGE (k:WinRegKey {hash: ck.hash})
        MERGE (p)-[:HAS_CHILD {name: ck.name}]->(k)
    )
    """

    cypher_query_with_backoff(query, {
        "parent_hash": node.hash,
        "child_values": child_values,
        "child_keys": child_keys,
    })
```

## Merkle Hashing Mechanics

### Bottom-Up Computation

Hashes are computed from leaves to root:

```
Field1 (Blob):   hash("offset-type")                        = hash1
Field2 (Blob):   hash("offset-type")                        = hash2
Struct (Tree):   hash("field1" + hash1 + "field2" + hash2 + "size-kind") = hash3
```

**Key Properties**:
1. **Deterministic**: Same input always produces same hash
2. **Hierarchical**: Parent hash includes all descendant hashes
3. **Tamper-proof**: Changing any node changes all ancestor hashes
4. **Content-addressed**: Hash represents content, not identity

### Example: Registry Key Hash

```
Value1 (Blob):   hash("Version" + "1.0" + "REG_SZ")         = hashA
Value2 (Blob):   hash("Build" + "19045" + "REG_DWORD")      = hashB
SubKey (Tree):   hash("Policies" + hashC + ...)             = hashC
Key (Tree):      hash("Version" + hashA + "Build" + hashB + "Policies" + hashC) = hashD
```

## Blob vs Tree Labels

### MerkleLabel.Blob (Leaves)

**Characteristics**:
- Leaf nodes in the hierarchy
- No children or terminal nodes
- Represent atomic data (values, fields, etc.)

**Examples**:
- `WinStructFieldMerkleNode` - Struct field with offset/type
- `WinRegValueMerkleNode` - Registry value with data
- `SyscallMerkleNode` - Individual syscall entry (future)

**Neo4j**: Created as terminal nodes without further traversal.

### MerkleLabel.Tree (Internal Nodes)

**Characteristics**:
- Internal nodes with children
- Represent containers or aggregates
- Hash includes all descendant hashes

**Examples**:
- `WinStructMerkleNode` - Struct containing fields
- `WinRegKeyMerkleNode` - Registry key containing subkeys/values
- `SyscallTableMerkleNode` - Table containing syscalls (future)

**Neo4j**: Recursively inserted, creating relationships to children.

## Neo4j Insertion Pattern

### 1. Hash-Based MERGE (Idempotent)

```cypher
MERGE (n:NodeType {hash: $hash})
ON CREATE SET n.property1 = $val1, n.property2 = $val2
ON MATCH SET n.property1 = $val1, n.property2 = $val2
```

**Benefits**:
- Same hash = same node (no duplicates)
- Re-running is safe (idempotent)
- Natural deduplication

### 2. Relationship with Name Property

```cypher
MERGE (parent)-[:RELATIONSHIP_TYPE {name: $name}]->(child)
```

**Purpose**:
- `name` property enables diff algorithm HashMap lookups
- Preserves hierarchical structure (field names, subkey names, etc.)
- Required for diff algorithm (see `docs/reference/architecture.md`)

### 3. Connecting to Filesystem Blob

```cypher
MATCH (b:Blob {hash: $blob_hash})
WITH b
MATCH (data:PluginNode {hash: $data_hash})
WITH b, data
MERGE (b)-[:HAS_PLUGIN_DATA {name: $name}]->(data)
```

**Purpose**:
- Links plugin-extracted data to source file (PE, registry hive, vmlinuz)
- Enables querying: "What structs are in this binary?"
- Maintains provenance

### 4. Batch Operations with UNWIND

```cypher
UNWIND $items AS item
MERGE (n:NodeType {hash: item.hash})
SET n.prop1 = item.prop1, n.prop2 = item.prop2
```

**Benefits**:
- Single query for multiple nodes
- Reduced network round-trips
- Better performance for large datasets

## Benefits of This Architecture

### 1. Content Deduplication

**Same data = same hash = single Neo4j node**

Example: If two binaries contain identical structs (e.g., `_LIST_ENTRY`), they share the same `WinStruct` node in Neo4j.

```cypher
(kernel32.dll:Blob)-[:HAS_STRUCT {name: "_LIST_ENTRY"}]->(struct:WinStruct {hash: "abc123"})
(ntdll.dll:Blob)-[:HAS_STRUCT {name: "_LIST_ENTRY"}]->(struct:WinStruct {hash: "abc123"})
                                                             ↑
                                                        Same node!
```

### 2. Tamper Detection

**Changing any node changes all ancestor hashes**

```
Change Field1 offset → Field1 hash changes
                    → Struct hash changes (includes Field1 hash)
                    → Easily detected in Neo4j diff
```

### 3. Efficient Change Detection

**Compare hashes to detect changes**

```cypher
MATCH (v1:Commit {hash: $commit1})-[:OWNS_FILESYSTEM]->(fs1:Tree)
MATCH (v2:Commit {hash: $commit2})-[:OWNS_FILESYSTEM]->(fs2:Tree)
WHERE fs1.hash <> fs2.hash
// Something changed, recurse to find what
```

### 4. Separation of Concerns

- **Domain logic**: Node classes (tree structure, business rules)
- **Hashing logic**: MerkleVisitor (traversal, hash computation)
- **Storage logic**: Cypher queries (persistence, relationships)

### 5. Extensibility

**Add new plugins by implementing the pattern:**
1. Create domain Node subclasses
2. Create MerkleNode subclasses
3. Implement MerkleVisitor with visit_* methods
4. Write Cypher insertion queries

### 6. Git-Like Properties

- **Content-addressed**: Nodes identified by hash, not ID
- **Immutable**: Hash changes if content changes
- **Merkle tree**: Hierarchical integrity verification
- **Efficient diffing**: Compare hashes to detect changes

## Implementation Checklist for New Plugins

When creating a new plugin that needs to store hierarchical data in Neo4j:

### Step 1: Domain Node Classes

- [ ] Subclass `neogit.core.model.Node`
- [ ] Implement `iter_child_nodes()` for internal nodes
- [ ] Return empty iterator for leaf nodes
- [ ] Store domain-specific data as attributes

Example:
```python
@define(auto_attribs=True)
class SyscallTableNode(Node):
    arch: str
    kernel_version: str
    syscalls: List[Dict]

    def iter_child_nodes(self) -> Iterator[Node]:
        for sc in self.syscalls:
            yield SyscallNode(
                name=sc["name"],
                index=sc["index"],
                entry_point=sc["entry_point"],
                parameters=sc["parameters"]
            )

@define(auto_attribs=True)
class SyscallNode(Node):
    name: str
    index: int
    entry_point: str
    parameters: List[str]

    def iter_child_nodes(self) -> Iterator[Node]:
        return iter([])  # Leaf node
```

### Step 2: MerkleNode Classes

- [ ] Subclass `neogit.core.model.MerkleNode`
- [ ] Add domain-specific fields as `field(kw_only=True)`
- [ ] Inherit: `hash`, `label`, `children`

Example:
```python
@define(auto_attribs=True)
class SyscallTableMerkleNode(MerkleNode):
    arch: str = field(kw_only=True)
    kernel_version: str = field(kw_only=True)

@define(auto_attribs=True)
class SyscallMerkleNode(MerkleNode):
    name: str = field(kw_only=True)
    index: int = field(kw_only=True)
    entry_point: str = field(kw_only=True)
    parameters: str = field(kw_only=True)  # JSON serialized
```

### Step 3: MerkleVisitor Implementation

- [ ] Subclass `neogit.core.merkle.MerkleVisitor`
- [ ] Implement `visit_<NodeType>()` for each domain Node type
- [ ] Compute hashes bottom-up (visit children first)
- [ ] Return `VisitedNode(original_node, merkle_node)`
- [ ] Assign correct `MerkleLabel` (Blob for leaves, Tree for internal)

Example:
```python
class SyscallsMerkleVisitor(MerkleVisitor):
    def visit_SyscallNode(self, node: SyscallNode, hash_obj: hashlib._Hash):
        # Hash syscall data
        params_json = json.dumps(node.parameters, sort_keys=True)
        data = f"{node.index}-{node.name}-{node.entry_point}-{params_json}".encode()
        hash_obj.update(data)

        merkle_node = SyscallMerkleNode(
            hash=hash_obj.hexdigest(),
            label=MerkleLabel.Blob,  # Leaf node
            name=node.name,
            index=node.index,
            entry_point=node.entry_point,
            parameters=params_json,
        )
        return VisitedNode(node, merkle_node)

    def visit_SyscallTableNode(self, node: SyscallTableNode, hash_obj: hashlib._Hash):
        children = {}

        # Visit all syscall children
        for syscall_node in node.iter_child_nodes():
            visited = self.visit(syscall_node)
            merkle_child = visited.return_value

            # Accumulate child hash
            data = f"{syscall_node.name}{merkle_child.hash}\n".encode()
            hash_obj.update(data)

            children[syscall_node.name] = merkle_child

        # Add table metadata
        hash_obj.update(f"{node.arch}-{node.kernel_version}".encode())

        merkle_node = SyscallTableMerkleNode(
            hash=hash_obj.hexdigest(),
            children=children,
            label=MerkleLabel.Tree,  # Internal node
            arch=node.arch,
            kernel_version=node.kernel_version,
        )
        return VisitedNode(node, merkle_node)
```

### Step 4: Cypher Insertion Methods

- [ ] Create MERGE queries using hash as unique key
- [ ] Use UNWIND for batch operations
- [ ] Separate Blob children from Tree children
- [ ] Create relationships with `{name: str}` property
- [ ] Use `cypher_query_with_backoff()` for resilience

Example:
```python
def insert_syscall_table_cypher(self, blob_hash: str, table_node: SyscallTableMerkleNode):
    # Collect syscall children for UNWIND
    syscalls = []
    for syscall_name, syscall_node in table_node.children.items():
        if isinstance(syscall_node, SyscallMerkleNode):
            syscalls.append({
                "name": syscall_name,
                "hash": syscall_node.hash,
                "index": syscall_node.index,
                "entry_point": syscall_node.entry_point,
                "parameters": syscall_node.parameters,
            })

    query = """
    MERGE (t:SyscallTable {hash: $table_hash, arch: $arch})
    WITH t
    UNWIND $syscalls AS sc
    MERGE (s:Syscall {hash: sc.hash, index: sc.index, name: sc.name,
                     entry_point: sc.entry_point, parameters: sc.parameters})
    MERGE (t)-[:HAS_SYSCALL {name: sc.name, index: sc.index}]->(s)
    WITH t
    MATCH (b:Blob {hash: $blob_hash})
    MERGE (b)-[:HAS_SYSCALL_TABLE {name: $arch}]->(t)
    """

    cypher_query_with_backoff(query, {
        "table_hash": table_node.hash,
        "arch": table_node.arch,
        "syscalls": syscalls,
        "blob_hash": blob_hash,
    })
```

### Step 5: Constraints

- [ ] Implement `constraints_data()` method
- [ ] Add unique constraint on hash for each node type

Example:
```python
def constraints_data(self) -> List[UniqueConstraint]:
    return [
        UniqueConstraint(label="SyscallTable", property_list=["hash"]),
        UniqueConstraint(label="Syscall", property_list=["hash"]),
    ]
```

### Step 6: Main Plugin Entry Point

- [ ] Create domain Nodes from source data
- [ ] Instantiate MerkleVisitor with `thread=True` for async
- [ ] Call `visitor.run_visit(root_node)`
- [ ] Iterate results with `visitor.as_gen()`
- [ ] Insert each MerkleNode into Neo4j

Example:
```python
def run(self, commit: Commit):
    fs = commit.filesystem.single()
    boot = get_boot_directory(fs)
    kernel_infos = find_kernel_versions(boot, self)

    with SyscallsMerkleVisitor(thread=True) as visitor:
        for kernel_info in kernel_infos:
            # Extract syscalls from git repo
            syscalls_data = extract_syscalls(kernel_info.version)

            # Create domain node
            table_node = SyscallTableNode(
                arch=kernel_info.architecture,
                kernel_version=kernel_info.version,
                syscalls=syscalls_data
            )

            # Visit to compute hashes
            visitor.run_visit(table_node)

        # Insert into Neo4j
        for visited_node in visitor.as_gen():
            merkle_node = visited_node.return_value
            self.insert_syscall_table_cypher(
                blob_hash=kernel_info.blob_hash,
                table_node=merkle_node
            )
```

## Code Examples

### Example 1: WinStructNode with iter_child_nodes()

```python
@define(auto_attribs=True)
class WinStructNode(Node):
    name: str
    struct_data: Dict
    kind: UserTypeKindType = field(init=False)
    size: int = field(init=False)

    def __attrs_post_init__(self):
        self.kind = UserTypeKindType[self.struct_data["kind"]]
        self.size = self.struct_data["size"]

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        """Yield WinStructFieldNode for each struct field."""
        for field_name, field_data in self.struct_data.get("fields", {}).items():
            yield WinStructFieldNode(name=field_name, field_data=field_data)
```

### Example 2: visit_WinStructNode() Hash Computation

```python
def visit_WinStructNode(self, node: WinStructNode, hash_obj: hashlib._Hash):
    children = {}

    # Bottom-up: visit all children first
    for member in node.iter_child_nodes():
        visited_node = self.visit(member)              # Recursive call
        merkle_node = visited_node.return_value        # Extract MerkleNode

        # Accumulate: child name + child hash
        data = f"{member.name}{merkle_node.hash}\n".encode()
        hash_obj.update(data)

        children[member.name] = merkle_node

    # Add parent-specific data
    hash_obj.update(f"{node.size}-{node.kind.name}".encode())

    # Create MerkleNode with final hash
    merkle_node = WinStructMerkleNode(
        hash=hash_obj.hexdigest(),      # SHA1 of: all fields + size + kind
        children=children,               # Dict[str, MerkleNode]
        label=MerkleLabel.Tree,          # Internal node
        name=node.name,
        size=node.size,
        kind=node.kind,
    )
    return VisitedNode(node, merkle_node)
```

### Example 3: Cypher MERGE with Hash-Based Deduplication

```python
query = """
MERGE (s:WinStruct {hash: $hash})
ON CREATE SET
    s.size = $size,
    s.kind = $kind
ON MATCH SET
    s.size = $size,
    s.kind = $kind
WITH s
UNWIND $fields AS f
MERGE (field:WinStructField {hash: f.hash})
ON CREATE SET
    field.offset = f.offset,
    field.data_type = f.data_type
MERGE (s)-[:HAS_FIELD {name: f.name}]->(field)
WITH s
MATCH (b:Blob {hash: $blob_hash})
MERGE (b)-[:HAS_STRUCT {name: $struct_name}]->(s)
"""
```

**Key Points**:
- `MERGE` on hash ensures no duplicates
- `ON CREATE SET` / `ON MATCH SET` updates properties
- Relationship creation with `{name: property}`
- Final connection to source Blob

### Example 4: Separating Children by MerkleLabel

```python
# registry.py pattern
child_values = [
    {"name": name, "hash": child.hash, "value": child.value.value}
    for name, child in node.children.items()
    if child.label == MerkleLabel.Blob        # Leaf values
]

child_keys = [
    {"name": name, "hash": child.hash}
    for name, child in node.children.items()
    if child.label == MerkleLabel.Tree        # Internal keys
]

# Create different Neo4j nodes for each type
query = """
MERGE (p:WinRegKey {hash: $parent_hash})
FOREACH (cv IN $child_values |
    MERGE (v:WinRegValue {hash: cv.hash, value: cv.value})
    MERGE (p)-[:HAS_CHILD {name: cv.name}]->(v)
)
FOREACH (ck IN $child_keys |
    MERGE (k:WinRegKey {hash: ck.hash})
    MERGE (p)-[:HAS_CHILD {name: ck.name}]->(k)
)
"""
```

## References

### Implementation Examples

- **Symbols Plugin**: `/home/wenzel/Projets/grapheos-plugins/plugins/plugins/symbols.py`
  - Complex hierarchical data (structs with fields, datatypes)
  - Multiple visitor methods for different node types
  - Batch insertion with UNWIND

- **Registry Plugin**: `/home/wenzel/Projets/grapheos-plugins/plugins/plugins/registry.py`
  - Tree-structured data (keys with subkeys and values)
  - Separation of Blob vs Tree children
  - Recursive insertion pattern

### Neogit Core Classes

- **Node**: `neogit.core.model.Node`
- **MerkleNode**: `neogit.core.model.MerkleNode`
- **MerkleVisitor**: `neogit.core.merkle.MerkleVisitor`
- **VisitedNode**: `neogit.core.visitor.VisitedNode`

### Related Documentation

- [Syscall Data Model Specification](syscall-data-model.md) - Specific application for syscall data
- [Diff Algorithm Documentation](/home/wenzel/Projets/osw-frontend/docs/reference/architecture.md) - Why relationship `name` property is required

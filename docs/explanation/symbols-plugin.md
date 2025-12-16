# Symbols Plugin Architecture

## Overview

The SymbolsPlugin extracts debugging symbols and type information from Windows PE files (ntoskrnl.exe, ntdll.dll, kernel32.dll) by parsing their associated PDB (Program Database) files. It creates a content-addressed graph representation of:

- **Symbols**: Function names and addresses
- **User-defined types**: Structs, unions, enums with their fields
- **Data types**: Complex recursive type definitions (pointers, arrays, bitfields)

This plugin is one of the most complex in the GraphEOS ecosystem due to:

1. **External dependencies**: Volatility3 for PDB parsing, symbol server downloads
2. **Recursive data structures**: WinDataType nodes can contain nested type hierarchies
3. **Large datasets**: ntoskrnl.exe PDB contains ~10,000 structs with ~100,000 fields
4. **Multi-stage pipeline**: Download → Parse → Transform → Hash → Insert

## Recent Refactoring

The plugin was refactored in December 2024 to improve testability, fix critical bugs, and separate concerns. The refactoring included:

### Phase 1: Bug Fixes

Five bugs were identified and fixed:

| Bug | Location | Severity | Fix |
|-----|----------|----------|-----|
| Silent error swallowing | Line 354 | High | Uncommented error logging for PDB failures |
| ValueError format string | Lines 380, 386 | High | Changed `ValueError("msg %s", arg)` to `ValueError(f"msg {arg}")` |
| Temp file not flushed | Line 388 | Medium | Added `tmp_file.flush()` before returning path |
| Temp file cleanup race | Lines 356-360 | Medium | Fixed cleanup with try/finally block |
| Variable shadowing | Line 357 | Low | Renamed `tmp_file` to `tmp_file_path` to avoid shadowing |

### Phase 2-3: Layered Architecture

The plugin was refactored into a three-layer architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    SymbolsPlugin (symbols.py)               │
│  - Orchestration and business logic                         │
│  - PDB download via Volatility3                             │
│  - Merkle visitor instantiation                             │
│  - Transaction management                                   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│              Service Layer (symbols_service.py)             │
│  - Pure functions (no side effects)                         │
│  - filter_valid_filenames()                                 │
│  - parse_symbols_from_json()                                │
│  - Testable with unit tests                                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│          Repository Layer (symbols_repository.py)           │
│  - Neo4j database operations (Cypher queries)               │
│  - query_pe_blobs()                                         │
│  - insert_symbols()                                         │
│  - insert_struct()                                          │
│  - insert_data_type()                                       │
└─────────────────────────────────────────────────────────────┘
```

**Benefits**:
- **Testability**: Pure functions can be unit tested without Neo4j
- **Separation of concerns**: Business logic separated from database operations
- **Maintainability**: Clear boundaries between layers
- **Dependency injection**: Repository injected via property, enabling mocking

### Phase 4: Unit Tests

27 unit tests were added:

- `tests/plugins/symbols/test_service.py`: 14 tests for pure functions (100% coverage)
- `tests/plugins/symbols/test_models.py`: 13 tests for data models

## Data Model

### Node Types

The symbols plugin creates four main node types in Neo4j:

```mermaid
graph TD
    Blob[Blob: ntoskrnl.exe] -->|HAS_SYMBOL {name}| Symbol
    Blob -->|HAS_STRUCT {name}| WinStruct
    WinStruct -->|HAS_FIELD {name}| WinStructField
    WinStructField -->|HAS_DATA_TYPE| WinDataType
    WinDataType -->|HAS_DATA_TYPE| WinDataType2[WinDataType]
    WinDataType2 -->|HAS_DATA_TYPE| WinDataType3[WinDataType]

    style Blob fill:#e1f5ff
    style Symbol fill:#fff3cd
    style WinStruct fill:#d4edda
    style WinStructField fill:#f8d7da
    style WinDataType fill:#d1ecf1
    style WinDataType2 fill:#d1ecf1
    style WinDataType3 fill:#d1ecf1
```

#### 1. Symbol Node

Represents a function or global variable exported by the PE file.

| Property | Type | Description |
|----------|------|-------------|
| `hash` | string | SHA1(address) - unique identifier |
| `address` | string | Memory address (stored as string for 64-bit precision) |

**Relationship**: `(:Blob)-[:HAS_SYMBOL {name: "NtCreateFile"}]->(:Symbol)`

**Example**:
```cypher
(:Blob {hash: "abc123"})-[:HAS_SYMBOL {name: "NtCreateFile"}]->
  (:Symbol {hash: "def456", address: "4096"})
```

**Source**: Parsed from PDB JSON `symbols` section

#### 2. WinStruct Node

Represents a user-defined type: struct, union, or enum.

| Property | Type | Description |
|----------|------|-------------|
| `hash` | string | Merkle hash: SHA1(fields + size + kind) |
| `size` | integer | Size in bytes |
| `kind` | string | "Struct", "Union", or "Enum" |

**Relationship**: `(:Blob)-[:HAS_STRUCT {name: "_EPROCESS"}]->(:Struct)`

**Hash Computation**:
```python
hash = SHA1(
    "field1_name" + field1_hash + "\n" +
    "field2_name" + field2_hash + "\n" +
    ... (all fields sorted by name) ...
    f"{size}-{kind}"
)
```

**Example**:
```cypher
(:Blob {hash: "abc123"})-[:HAS_STRUCT {name: "_EPROCESS"}]->
  (:Struct {hash: "ghi789", size: 1024, kind: "Struct"})
```

**Source**: Parsed from PDB JSON `user_types` section

#### 3. WinStructField Node

Represents a field within a struct/union or a constant in an enum.

| Property | Type | Description |
|----------|------|-------------|
| `hash` | string | SHA1(offset + data_type) |
| `offset` | integer | Byte offset within parent struct (or enum constant value) |
| `data_type` | string | JSON-encoded type definition |

**Relationship**: `(:Struct)-[:HAS_FIELD {name: "UniqueProcessId"}]->(:StructField)`

**data_type Format**: JSON string representing type metadata:
```json
{
  "kind": "pointer",
  "subtype": {
    "kind": "base",
    "name": "void"
  }
}
```

**Example**:
```cypher
(:Struct {hash: "ghi789"})-[:HAS_FIELD {name: "UniqueProcessId"}]->
  (:StructField {
    hash: "jkl012",
    offset: 1088,
    data_type: '{"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}'
  })
```

**Special Case - Enums**: For enum types, each constant becomes a WinStructField where:
- `offset` stores the constant's integer value
- `data_type` is omitted or empty

**Source**: Parsed from PDB JSON field definitions

#### 4. WinDataType Node (Recursive)

Represents complex type definitions that can reference other types.

| Property | Type | Description |
|----------|------|-------------|
| `hash` | string | Merkle hash computed from type hierarchy |
| `type` | string | FieldKindType enum value (Base, Pointer, Array, etc.) |
| `name` | string | Type name (for base types, structs, etc.) |
| `array_counter` | integer | Array element count (for Array type) |
| `bit_position` | integer | Bit offset within field (for Bitfield type) |
| `bit_length` | integer | Bit width (for Bitfield type) |

**Relationship**: `(:DataType)-[:HAS_DATA_TYPE]->(:DataType)`

**FieldKindType Values**:
- `Base`: Primitive types (int, char, void, etc.)
- `Pointer`: Pointer to another type
- `Array`: Fixed-size array of elements
- `Struct`, `Union`, `Enum`: References to user-defined types
- `Bitfield`: Bit-level field within a struct
- `Function`: Function pointer type

**Example - Pointer to Array**:
```cypher
(:DataType {hash: "xyz123", type: "Pointer", name: null})-[:HAS_DATA_TYPE]->
  (:DataType {hash: "xyz456", type: "Array", array_counter: 10})-[:HAS_DATA_TYPE]->
    (:DataType {hash: "xyz789", type: "Struct", name: "_EPROCESS"})
```

This represents: `_EPROCESS (*)[10]` - pointer to array of 10 _EPROCESS structs

**Merkle Hashing**: WinDataType nodes use content-addressed hashing:
- Hash includes: type, name, array_counter, bit_position, bit_length, and all child hashes
- Identical type definitions share the same node in Neo4j (deduplication)

## PDB Processing Pipeline

### Step 1: Identify Target PE Files

```python
# symbols.py:325-333
def run(self, commit: Commit):
    fs = commit.filesystem.single()

    # Query for PE files (application/x-dosexec MIME type)
    blob_results = self.repository.query_pe_blobs(
        root_hash=fs.hash,
        mime_type="application/x-dosexec"
    )

    # Filter to only allowed filenames
    valid_blobs = filter_valid_filenames(
        blob_results,
        allowed_filenames=["ntoskrnl.exe", "ntdll.dll", "kernel32.dll"]
    )
```

**Repository Method** (`symbols_repository.py:20-39`):
```python
def query_pe_blobs(self, root_hash: str, mime_type: str) -> List[Tuple[PurePath, str]]:
    query = """
    MATCH path = (r:Tree {hash: $root_hash})-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
    WHERE EXISTS {
        MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType)
        WHERE m.mime = $mime_type
    }
    RETURN [rel IN relationships(path) | rel.name] AS parts, b.hash
    """
    rows, _ = self.neogit.db.cypher_query(query, {"mime_type": mime_type, "root_hash": root_hash})
    return [(PurePath(*row[0]), row[1]) for row in rows]
```

**Service Function** (`symbols_service.py:11-19`):
```python
def filter_valid_filenames(
    blob_results: List[Tuple[PurePath, str]], allowed_filenames: List[str]
) -> List[Tuple[PurePath, str]]:
    """Filter blob results to only include allowed filenames.

    Pure function - testable without Neo4j.
    """
    return [(path, blob_hash) for path, blob_hash in blob_results if path.name in allowed_filenames]
```

### Step 2: Download and Parse PDB

```python
# symbols.py:341-390
def handle_pdb(self, blob_hash: str) -> Tuple[str, str, Path]:
    """Download PE, extract PDB info, download PDB from symbol server."""

    # Download PE file from neogit
    with self.downloaded_file(blob_hash) as local_file:
        # Extract GUID and PDB name using LIEF
        pe = lief.parse(str(local_file))
        pdb_name = pe.debug[0].filename
        guid = pe.debug[0].guid
        age = pe.debug[0].age

    # Download PDB from Microsoft symbol server via Volatility3
    pdb_path = windows.pdbutil.PDBUtility.download_pdb_isf(
        guid=guid,
        file_name=pdb_name,
        progress_callback=SilentProgress(),
    )

    if not pdb_path:
        raise ValueError(f"Failed to retrieve PDB {pdb_name} on {blob_hash}")

    # Parse PDB to JSON using Volatility3
    with open(pdb_path, "rb") as pdb_file:
        pdb_parser = pdbconv.PDBRetreiver(context=None, file_path=pdb_path)
        pdb_parser.open()
        j_data = pdb_parser.read_json()

    # Write to temporary file
    tmp_file = NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(j_data, tmp_file)
    tmp_file.flush()  # BUG FIX: ensure data is written

    return blob_hash, pdb_name, Path(tmp_file.name)
```

**Key Dependencies**:
- **LIEF**: PE parsing library to extract debug info (GUID, PDB name)
- **Volatility3**: Downloads PDB from Microsoft symbol server and parses to JSON
- **Symbol Server**: `https://msdl.microsoft.com/download/symbols/`

**PDB JSON Structure**:
```json
{
  "symbols": {
    "NtCreateFile": {"address": 4096},
    "KeInitializeThread": {"address": 8192}
  },
  "user_types": {
    "_EPROCESS": {
      "kind": "struct",
      "size": 1024,
      "fields": {
        "UniqueProcessId": {
          "offset": 1088,
          "type": {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}
        }
      }
    }
  }
}
```

#### Manual PDB Extraction (Testing/Development)

For testing or offline development, you can manually extract PDB JSON using Volatility3's `pdbconv.py` tool:

```bash
# Download and convert PDB to JSON
python volatility3/framework/symbols/windows/pdbconv.py \
    -g 55678bc384f099b6ed05e9e39046924a1 \
    -p ntkrnlmp.pdb \
    -o ntkrnlmp.json
```

**Parameters**:
- `-g`: PDB GUID + age (concatenated, typically from PE debug directory)
- `-p`: PDB filename (e.g., `ntkrnlmp.pdb` for ntoskrnl.exe)
- `-o`: Output JSON file path

This downloads the PDB from Microsoft's symbol server, parses it, and writes the JSON to disk. The resulting file can be used directly with the plugin or for developing test fixtures.

**Use cases**:
- Creating test fixtures with real PDB data
- Offline development without symbol server access
- Debugging PDB parsing issues
- Examining PDB structure for specific Windows builds

### Step 3: Parse Symbols

```python
# symbols.py:351-355
try:
    with open(tmp_file_path, "r") as f:
        j_data = json.load(f)
    self.parse_pdb_json(blob_hash, pdb_name, j_data)
finally:
    with contextlib.suppress(FileNotFoundError):
        os.remove(tmp_file_path)
```

**Parse Symbols** (`symbols.py:393-408`):
```python
def parse_pdb_json(self, blob_hash: str, pdb_name: str, j_pdb: Dict):
    # Parse symbols section
    if "symbols" in j_pdb:
        symbols = parse_symbols_from_json(j_pdb["symbols"])

        # Batch insert into Neo4j
        param_list = [
            {"hash": sym["hash"], "sym_name": sym["name"], "address": sym["address"]}
            for sym in symbols
        ]
        self.repository.insert_symbols(blob_hash, param_list)
```

**Service Function** (`symbols_service.py:22-42`):
```python
def parse_symbols_from_json(symbols_dict: Dict) -> List[Dict[str, str]]:
    """Parse symbols from PDB JSON, filtering mangled names.

    Filters out:
    - C++ mangled names starting with '?'
    - Compiler-generated symbols starting with '$'

    Returns sorted list of {name, address, hash} dicts.
    """
    entries = []
    for sym, value in sorted(symbols_dict.items()):
        if sym.startswith("?") or sym.startswith("$"):
            continue  # Skip mangled and compiler symbols

        address = str(value["address"])  # Store as string for 64-bit precision
        entries.append({
            "name": sym,
            "address": address,
            "hash": hashlib.sha1(address.encode()).hexdigest()
        })

    return entries
```

**Repository Method** (`symbols_repository.py:41-55`):
```python
def insert_symbols(self, blob_hash: str, param_list: List[Dict]) -> None:
    query = """
    MATCH (b:Blob {hash: $blob_hash})
    WITH b
    UNWIND $unwind as p
    MERGE (s:Symbol {hash: p.hash, address: p.address})
    MERGE (b)-[:HAS_SYMBOL {name: p.sym_name}]->(s)
    """
    cypher_query_with_backoff(query, {"blob_hash": blob_hash, "unwind": param_list})
```

### Step 4: Process User-Defined Types (Merkle Visitor)

```python
# symbols.py:410-428
if "user_types" in j_pdb:
    with SymbolsMerkleVisitor(thread=True) as visitor:
        # Create domain nodes for all structs
        for struct_name, struct_data in sorted(j_pdb["user_types"].items()):
            struct_node = StructNode(name=struct_name, struct_data=struct_data)
            visitor.run_visit(struct_node)

        # Retrieve computed Merkle nodes
        for visited_node in visitor.as_gen():
            merkle_node = visited_node.return_value

            # Insert into Neo4j
            if isinstance(merkle_node, StructMerkleNode):
                self.insert_struct_merkle(blob_hash, merkle_node)
            elif isinstance(merkle_node, DataTypeMerkleNode):
                self.repository.insert_data_type(merkle_node)
```

### Step 5: Compute Merkle Hashes

#### StructNode Visitor

```python
# symbols.py:228-251
def visit_StructNode(self, node: StructNode, hash_obj: hashlib._Hash):
    children = {}

    # Visit all field children (bottom-up)
    for member in node.iter_child_nodes():
        visited_node = self.visit(member)
        merkle_node = visited_node.return_value

        # Accumulate: field_name + field_hash
        data = f"{member.name}{merkle_node.hash}\n".encode()
        hash_obj.update(data)

        children[member.name] = merkle_node

    # Add struct metadata: size and kind
    hash_obj.update(f"{node.size}-{node.kind.name}".encode())

    # Create Merkle node
    merkle_node = StructMerkleNode(
        hash=hash_obj.hexdigest(),
        children=children,
        label=MerkleLabel.Tree,  # Internal node (has fields)
        name=node.name,
        size=node.size,
        kind=node.kind,
    )
    return VisitedNode(node, merkle_node)
```

**Hash Formula**:
```
hash(_EPROCESS) = SHA1(
    "UniqueProcessId" + hash(field1) + "\n" +
    "ImageFileName" + hash(field2) + "\n" +
    "ActiveProcessLinks" + hash(field3) + "\n" +
    ... (all fields, sorted alphabetically) ...
    "1024-struct"
)
```

#### StructFieldNode Visitor

```python
# symbols.py:253-280
def visit_StructFieldNode(self, node: StructFieldNode, hash_obj: hashlib._Hash):
    # Hash field offset
    hash_obj.update(str(node.offset).encode())

    # Hash field type (recursively visit data type if complex)
    if "type" in node.field_data:
        type_node = DataTypeNode(type_data=node.field_data["type"])
        visited_type = self.visit(type_node)
        merkle_type = visited_type.return_value

        hash_obj.update(merkle_type.hash.encode())

        # Store JSON-encoded type for Neo4j
        data_type_json = json.dumps(node.field_data["type"])
    else:
        data_type_json = ""

    merkle_node = StructFieldMerkleNode(
        hash=hash_obj.hexdigest(),
        label=MerkleLabel.Blob,  # Leaf node
        name=node.name,
        offset=node.offset,
        data_type=data_type_json,
    )
    return VisitedNode(node, merkle_node)
```

#### DataTypeNode Visitor (Recursive)

```python
# symbols.py:282-320
def visit_DataTypeNode(self, node: DataTypeNode, hash_obj: hashlib._Hash):
    children = {}

    # Hash type kind and name
    hash_obj.update(node.kind.name.encode())
    if node.name:
        hash_obj.update(node.name.encode())

    # Hash optional metadata
    if node.array_counter is not None:
        hash_obj.update(str(node.array_counter).encode())
    if node.bit_position is not None:
        hash_obj.update(str(node.bit_position).encode())
    if node.bit_length is not None:
        hash_obj.update(str(node.bit_length).encode())

    # Recursively visit child types (e.g., pointer subtype, array element type)
    for child_node in node.iter_child_nodes():
        visited_child = self.visit(child_node)
        merkle_child = visited_child.return_value

        hash_obj.update(merkle_child.hash.encode())
        children[merkle_child.hash] = merkle_child

    merkle_node = DataTypeMerkleNode(
        hash=hash_obj.hexdigest(),
        children=children,
        label=MerkleLabel.Tree if children else MerkleLabel.Blob,
        kind=node.kind,
        name=node.name,
        array_counter=node.array_counter,
        bit_position=node.bit_position,
        bit_length=node.bit_length,
    )
    return VisitedNode(node, merkle_node)
```

**Example - Pointer to Array of Structs**:

Type: `_EPROCESS (*)[10]`

```
DataTypeNode(kind=Pointer)
  └─ child: DataTypeNode(kind=Array, array_counter=10)
       └─ child: DataTypeNode(kind=Struct, name="_EPROCESS")

Hash computation (bottom-up):
1. hash(Struct) = SHA1("Struct" + "_EPROCESS") = "abc123"
2. hash(Array) = SHA1("Array" + "10" + "abc123") = "def456"
3. hash(Pointer) = SHA1("Pointer" + "def456") = "ghi789"
```

### Step 6: Insert into Neo4j

#### Insert Struct

```python
# symbols_repository.py:57-86
def insert_struct(self, blob_hash: str, struct_node, unwind_param: List[Dict]) -> None:
    query = """
    MERGE (s:Struct {hash: $hash, size: $size, kind: $kind})
    WITH s
    UNWIND $unwind_param as x
    MERGE (f:StructField {hash: x.hash, offset: x.offset, data_type: x.data_type})
    MERGE (s)-[:HAS_FIELD {name: x.name}]->(f)
    WITH s
    MATCH (b:Blob {hash: $blob_hash})
    WITH b, s
    MERGE (b)-[:HAS_STRUCT {name: $name}]->(s)
    """
    cypher_query_with_backoff(query, {
        "blob_hash": blob_hash,
        "unwind_param": unwind_param,
        "hash": struct_node.hash,
        "name": struct_node.name,
        "size": struct_node.size,
        "kind": struct_node.kind.name,
    })
```

**Batch Operation**: Uses `UNWIND` to insert all fields in a single query (performance optimization).

**unwind_param Structure**:
```python
[
    {
        "name": "UniqueProcessId",
        "hash": "field1_hash",
        "offset": 1088,
        "data_type": '{"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}'
    },
    {
        "name": "ImageFileName",
        "hash": "field2_hash",
        "offset": 1448,
        "data_type": '{"kind": "array", "count": 15, "subtype": {"kind": "base", "name": "char"}}'
    },
    # ... more fields
]
```

#### Insert Data Type (Recursive)

```python
# symbols_repository.py:88-141
def insert_data_type(self, node) -> None:
    # Collect all child nodes
    children = [
        {
            "hash": x.hash,
            "type": x.kind.name,
            "name": x.name,
            "array_counter": x.array_counter,
            "bit_position": x.bit_position,
            "bit_length": x.bit_length,
        }
        for hash, x in node.children.items()
    ]

    query = """
    MERGE (d:DataType {hash: $hash})
    ON CREATE SET
        d.type = CASE WHEN $type IS NOT NULL THEN $type END,
        d.name = CASE WHEN $name IS NOT NULL THEN $name END,
        d.array_counter = CASE WHEN $array_counter IS NOT NULL THEN $array_counter END,
        d.bit_position = CASE WHEN $bit_position IS NOT NULL THEN $bit_position END,
        d.bit_length = CASE WHEN $bit_length IS NOT NULL THEN $bit_length END
    ON MATCH SET
        d.type = CASE WHEN $type IS NOT NULL THEN $type END,
        d.name = CASE WHEN $name IS NOT NULL THEN $name END,
        d.array_counter = CASE WHEN $array_counter IS NOT NULL THEN $array_counter END,
        d.bit_position = CASE WHEN $bit_position IS NOT NULL THEN $bit_position END,
        d.bit_length = CASE WHEN $bit_length IS NOT NULL THEN $bit_length END
    WITH d
    UNWIND $children AS child
    MERGE (c:DataType {hash: child.hash})
    ON CREATE SET
        c.type = CASE WHEN child.type IS NOT NULL THEN child.type END,
        c.name = CASE WHEN child.name IS NOT NULL THEN child.name END,
        c.array_counter = CASE WHEN child.array_counter IS NOT NULL THEN child.array_counter END,
        c.bit_position = CASE WHEN child.bit_position IS NOT NULL THEN child.bit_position END,
        c.bit_length = CASE WHEN child.bit_length IS NOT NULL THEN child.bit_length END
    MERGE (d)-[:HAS_DATA_TYPE]->(c)
    """

    cypher_query_with_backoff(query, {
        "hash": node.hash,
        "type": node.kind.name,
        "name": node.name,
        "array_counter": node.array_counter,
        "bit_position": node.bit_position,
        "bit_length": node.bit_length,
        "children": children,
    })
```

**Idempotency**: Uses `MERGE` with hash as unique key, ensuring re-runs don't create duplicates.

**Conditional SET**: Uses `CASE WHEN ... IS NOT NULL` to avoid overwriting with null values.

## Testing Strategy

### Unit Tests (100% Coverage on Service Layer)

#### Service Function Tests

**`tests/plugins/symbols/test_service.py`**:

1. **TestFilterValidFilenames**: 5 tests
   - Filters allowed filenames
   - Returns empty for no matches
   - Preserves input order
   - Case-sensitive matching
   - Handles empty input

2. **TestParseSymbolsFromJson**: 9 tests
   - Parses valid symbols
   - Filters mangled names (starting with `?`)
   - Filters compiler symbols (starting with `$`)
   - Computes SHA1 hash of address
   - Stores address as string (64-bit compatibility)
   - Returns sorted output by name
   - Validates result structure

**Example Test**:
```python
def test_filters_mangled_names_with_question_mark(self):
    """Should filter out symbols starting with '?'."""
    symbols = {
        "NtCreateFile": {"address": 0x1000},
        "?mangled_name": {"address": 0x2000},
    }

    result = parse_symbols_from_json(symbols)

    assert len(result) == 1
    assert result[0]["name"] == "NtCreateFile"
```

#### Model Tests

**`tests/plugins/symbols/test_models.py`**:

1. **TestStructNode**: 7 tests
   - Struct kind detection
   - Union kind detection
   - Enum detection (by `constants` field)
   - Field iteration
   - Enum constant mapping (constants become fields)
   - Empty struct handling

2. **TestStructFieldNode**: 4 tests
   - Offset extraction
   - Data type JSON encoding
   - Complex nested type encoding
   - Field name preservation

3. **Enum Tests**: 2 tests
   - FieldKindType enum values
   - UserTypeKindType enum values

**Example Test**:
```python
def test_enum_detection_by_constants(self):
    """Should detect enum when constants field present."""
    data = {"size": 4, "constants": {"A": 0, "B": 1}}
    node = StructNode(name="TestEnum", struct_data=data)

    assert node.kind == UserTypeKindType.Enum
    assert node.size == 4
```

### Integration Tests (Not Implemented)

Integration tests are out of scope per user requirements, but would include:

- **Symbol Server Integration**: Testing actual PDB downloads from Microsoft
- **Neo4j End-to-End**: Full pipeline from PE file to graph insertion
- **Volatility3 Integration**: PDB parsing with real-world binaries

## Performance Characteristics

### Bottlenecks

1. **Symbol Server Downloads**: PDB files are large (ntoskrnl.exe PDB ~30MB)
   - Network latency: 5-30 seconds per PDB
   - Mitigated by Volatility3 local cache

2. **PDB Parsing**: JSON generation is CPU-intensive
   - ntoskrnl.exe: ~10 seconds
   - ntdll.dll: ~5 seconds

3. **Merkle Hashing**: Computing ~10,000 struct hashes
   - Parallel processing via `thread=True` in MerkleVisitor
   - ~5 seconds total

4. **Neo4j Insertion**: Batch operations via UNWIND
   - ~100,000 nodes for ntoskrnl.exe
   - ~30 seconds with backoff retry

### Optimizations

1. **Parallel Processing**:
   ```python
   with SymbolsMerkleVisitor(thread=True) as visitor:
       # Hashing runs in background thread
   ```

2. **Batch Insertion**:
   ```python
   UNWIND $unwind_param as x
   MERGE (f:StructField {hash: x.hash, ...})
   # Single query for all fields
   ```

3. **Lazy Repository Initialization**:
   ```python
   @property
   def repository(self) -> SymbolsRepository:
       if self._repository is None:
           self._repository = SymbolsRepository(self.neogit)
       return self._repository
   ```

4. **Filtered Filename Query**: Only process 3 specific PE files
   ```python
   allowed_filenames = ["ntoskrnl.exe", "ntdll.dll", "kernel32.dll"]
   ```

## Common Queries

### Find All Symbols in a PE File

```cypher
MATCH (b:Blob {hash: $blob_hash})-[r:HAS_SYMBOL]->(s:Symbol)
RETURN r.name AS symbol_name, s.address AS address
ORDER BY r.name
```

### Find All Structs with a Specific Field

```cypher
MATCH (s:Struct)-[r:HAS_FIELD {name: "UniqueProcessId"}]->(f:StructField)
MATCH (b:Blob)-[rel:HAS_STRUCT]->(s)
RETURN rel.name AS struct_name, b.hash AS source_file, f.offset AS field_offset
```

### Find Struct Definition Differences Between Two Commits

```cypher
MATCH (c1:Commit {hash: $commit1})-[:OWNS_FILESYSTEM]->(fs1:Tree)
MATCH (c2:Commit {hash: $commit2})-[:OWNS_FILESYSTEM]->(fs2:Tree)
MATCH (fs1)-[:HAS_CHILD_BLOB*]->(b1:Blob)-[r1:HAS_STRUCT {name: "_EPROCESS"}]->(s1:Struct)
MATCH (fs2)-[:HAS_CHILD_BLOB*]->(b2:Blob)-[r2:HAS_STRUCT {name: "_EPROCESS"}]->(s2:Struct)
WHERE s1.hash <> s2.hash
RETURN s1.hash AS old_hash, s2.hash AS new_hash, s1.size AS old_size, s2.size AS new_size
```

### Find All Pointer Types

```cypher
MATCH (d:DataType {type: "Pointer"})-[:HAS_DATA_TYPE]->(target:DataType)
RETURN d.hash, target.type AS points_to_type, target.name AS points_to_name
LIMIT 100
```

### Trace Complex Type Hierarchy

```cypher
MATCH path = (root:DataType {hash: $type_hash})-[:HAS_DATA_TYPE*]->(leaf:DataType)
WHERE NOT (leaf)-[:HAS_DATA_TYPE]->()
RETURN [n IN nodes(path) | {type: n.type, name: n.name, array_counter: n.array_counter}] AS type_chain
```

## Error Handling

### PDB Download Failures

```python
# symbols.py:378-386
try:
    pdb_path = windows.pdbutil.PDBUtility.download_pdb_isf(...)
except Exception as e:
    raise ValueError(f"Failed to retrieve PDB {pdb_name} on {blob_hash}") from e

if not pdb_path:
    raise ValueError(f"Failed to retrieve PDB {pdb_name} on {blob_hash}")
```

**Causes**:
- Symbol server unavailable
- Network timeout
- Invalid GUID/PDB name

**Resolution**: Logged and skipped (plugin continues with remaining files)

### JSON Parsing Errors

```python
# symbols.py:351-355
try:
    with open(tmp_file_path, "r") as f:
        j_data = json.load(f)
    self.parse_pdb_json(blob_hash, pdb_name, j_data)
finally:
    with contextlib.suppress(FileNotFoundError):
        os.remove(tmp_file_path)
```

**Causes**:
- Corrupted PDB file
- Volatility3 parsing failure
- Disk full during JSON write

**Resolution**: Exception propagates, temp file cleanup guaranteed

### Neo4j Connection Failures

```python
# neogit.service.neogit.cypher_query_with_backoff
@backoff.on_exception(
    backoff.expo,
    (TransientError, ServiceUnavailable),
    max_tries=5,
    max_time=60,
)
def cypher_query_with_backoff(query: str, params: Dict):
    # Retry with exponential backoff
```

**Causes**:
- Neo4j server restart
- Network interruption
- Transaction deadlock

**Resolution**: Automatic retry with exponential backoff (up to 60 seconds)

## Dependencies

### External Libraries

| Library | Purpose | Version Constraint |
|---------|---------|-------------------|
| volatility3 | PDB parsing and symbol server | `^2.5.0` |
| lief | PE file parsing (GUID extraction) | `^0.13.0` |
| neogit | Neo4j ORM and Merkle utilities | `^0.13.0` |
| attrs | Data class definitions | `^23.0.0` |

### System Dependencies

- **Symbol Server Access**: Requires internet connection to `https://msdl.microsoft.com/download/symbols/`
- **Neo4j Database**: Requires running Neo4j instance (configured via neogit)
- **Disk Space**: PDB cache can grow large (~1GB for multiple Windows versions)

## Future Improvements

### 1. Incremental Processing

Currently re-processes all PDB files on every run. Could track processed blobs:

```cypher
MATCH (b:Blob {hash: $blob_hash})-[:HAS_SYMBOL]->()
RETURN COUNT(*) > 0 AS already_processed
```

### 2. Parallel PDB Downloads

Use `ThreadPoolExecutor` for concurrent symbol server requests:

```python
with ThreadPoolExecutor(max_workers=3) as executor:
    futures = [executor.submit(handle_pdb, blob_hash) for blob_hash in blobs]
    for future in as_completed(futures):
        parse_pdb_json(*future.result())
```

### 3. Struct Field Relationship to WinDataType

Currently, `WinStructField.data_type` is a JSON string. Could create explicit relationship:

```cypher
(:StructField)-[:HAS_DATA_TYPE]->(:DataType)
```

This would enable graph queries like "find all structs with pointer fields".

### 4. Diff Algorithm Integration

The Merkle hashing enables efficient struct diffing:

```python
def diff_structs(old_hash: str, new_hash: str) -> List[str]:
    """Compare two struct versions and return changed fields."""
    # Compare child field hashes to identify changes
```

### 5. Cross-Reference with Symbols

Link struct fields to symbol addresses:

```cypher
MATCH (sym:Symbol)-[:REFERENCES_STRUCT]->(s:Struct)
WHERE sym.name =~ ".*_EPROCESS.*"
RETURN sym.name, s.hash
```

## References

### Source Files

- **Plugin**: `plugins/plugins/symbols.py` (500+ lines)
- **Service Layer**: `plugins/plugins/symbols_service.py` (42 lines, 100% coverage)
- **Repository Layer**: `plugins/plugins/symbols_repository.py` (142 lines)
- **Service Tests**: `tests/plugins/symbols/test_service.py` (175 lines)
- **Model Tests**: `tests/plugins/symbols/test_models.py` (149 lines)

### Related Documentation

- [Data Model Reference](../reference/data-model.md#symbolsplugin) - Neo4j schema
- [Neo4j Insertion Pattern](neo4j-insertion-pattern.md) - Merkle visitor architecture
- [Plugin API Reference](../reference/plugin-api.md) - AbstractPlugin base class
- [How to Query Data](../how-to/query-data.md) - Cypher query examples

### External Resources

- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [LIEF Documentation](https://lief-project.github.io/)
- [Microsoft Symbol Server](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-servers-and-symbol-stores)
- [PDB File Format](https://llvm.org/docs/PDB/)

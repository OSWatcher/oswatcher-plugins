# Syscall Data Model Specification

## Overview

This document specifies the Neo4j data model for storing Linux and Windows syscall information in the OSWatcher system. The design follows the hash-based, git-like architecture where all nodes are content-addressed and immutable.

## Motivation

OSWatcher needs to track syscall information from operating system snapshots for:
- Security analysis (identifying available attack surface)
- OS fingerprinting (kernel version detection)
- Change detection (tracking syscall additions/removals across versions)
- Cross-platform comparison (Linux vs Windows syscall differences)

## Architecture Context: Windows vs Linux Syscall Handling

Understanding the fundamental architectural differences between Windows and Linux syscall handling is critical to the data model design:

### Windows (x64)

The kernel exposes only **64-bit syscall tables**:
- **NT SSDT** (Native API syscalls)
- **Win32k SSDT** (Graphics/Window management syscalls)

**32-bit syscalls do NOT enter the kernel directly:**
- All 32-bit calls go through the **WoW64 user-mode thunking layer**
- WoW64 translates 32-bit syscall numbers → 64-bit equivalents
- WoW64 switches CPU mode
- WoW64 invokes the 64-bit syscall
- The kernel never processes a native 32-bit syscall ABI

→ **Windows uses user-mode translation; kernel only runs 64-bit syscalls.**

### Linux (x86-64)

The kernel contains **two real syscall tables**:
- **64-bit syscall table** (`syscall_64.tbl`)
- **32-bit compat syscall table** (`syscall_32.tbl`) when `CONFIG_COMPAT=y`

**32-bit processes execute real 32-bit syscalls:**
- A 32-bit process executes a 32-bit syscall instruction
- This traps directly into the kernel
- The kernel dispatches to:
  - `sys_*` functions (64-bit)
  - `compat_sys_*` functions (32-bit)
- Argument translation (pointers, struct layouts, time types) happens **in kernel**

→ **Linux uses in-kernel compat handling; both ABIs exist concurrently.**

### Implications for Data Model

**Linux:** Single kernel blob contains multiple architecture tables
```
vmlinuz blob → {x64 syscall table, x86 compat syscall table}
```

**Windows:** Different kernel blobs contain different syscall sources
```
ntoskrnl.exe blob → {NT SSDT (x64 only)}
win32k.sys blob → {Win32k SSDT (x64 only)}
```

## Data Model Design

The syscall data model follows the **hierarchical pattern** established by `WinStruct` (which has `WinStructField` children). This pattern:
- Uses intermediate container nodes (`SyscallTable` analogous to `WinStruct`)
- Enables recursive diffing in the existing diff algorithm
- Solves the relationship name uniqueness requirement naturally

### Node Hierarchy

```
Blob (vmlinuz, ntoskrnl.exe, win32k.sys)
  └─[HAS_SYSCALL_TABLE]→ SyscallTable (x64, x86, NT, Win32k)
      └─[HAS_SYSCALL]→ Syscall (read, write, open, etc.)
```

## Node Definitions

### SyscallTable

Represents a syscall table within a kernel binary.

**Properties:**
- `hash: String!` - SHA256 hash of: `arch + sorted(syscall_hashes)`
- `arch: String!` - Architecture: `"X64"` or `"X86"`

**Relationships:**
- **Incoming:** `(Blob)-[:HAS_SYSCALL_TABLE {name: String!}]->(SyscallTable)`
  - Relationship `name` property: architecture identifier or source name
    - Linux: `"x64"` or `"x86"`
    - Windows: `"nt"` or `"win32k"`
- **Outgoing:** `(SyscallTable)-[:HAS_SYSCALL {name: String!, index: Int!}]->(Syscall)`
  - Relationship `name` property: syscall name (e.g., `"read"`, `"write"`)
  - Relationship `index` property: syscall number

**Hash Calculation:**
```python
import hashlib
import json

def calculate_syscall_table_hash(arch: str, syscall_hashes: list[str]) -> str:
    """Calculate hash for SyscallTable node.

    Args:
        arch: "X64" or "X86"
        syscall_hashes: List of syscall hashes in table order

    Returns:
        SHA256 hash hex string
    """
    content = {
        "arch": arch,
        "syscalls": sorted(syscall_hashes)  # Sort for deterministic hash
    }
    content_str = json.dumps(content, sort_keys=True)
    return hashlib.sha256(content_str.encode()).hexdigest()
```

**Diff Algorithm Integration:**
- `SyscallTable` must be added to the list of recursable types in `TreeDiffRecursiveProcedure.java`:
  ```java
  private boolean isRecursableLabel(String type) {
      return "Tree".equals(type) || "WinRegKey".equals(type) ||
             "WinStruct".equals(type) || "WinStructField".equals(type) ||
             "SyscallTable".equals(type);  // Add this
  }
  ```

### Syscall

Represents an individual syscall entry with its signature.

**Properties:**
- `hash: String!` - SHA256 hash of: `index + name + entry_point + parameters`
- `index: Int!` - Syscall number
- `name: String!` - Human-readable syscall name (e.g., `"read"`, `"write"`)
- `entry_point: String!` - Kernel function name (e.g., `"sys_read"`, `"compat_sys_read"`)
- `parameters: [String!]!` - Parameter signatures (e.g., `["int fd", "char *buf", "size_t count"]`)

**Relationships:**
- **Incoming:** `(SyscallTable)-[:HAS_SYSCALL {name: String!, index: Int!}]->(Syscall)`

**Hash Calculation:**
```python
import hashlib
import json

def calculate_syscall_hash(index: int, name: str, entry_point: str,
                          parameters: list[str]) -> str:
    """Calculate hash for Syscall node.

    Args:
        index: Syscall number
        name: Syscall name (e.g., "read")
        entry_point: Kernel function (e.g., "sys_read")
        parameters: List of parameter signatures

    Returns:
        SHA256 hash hex string
    """
    content = {
        "index": index,
        "name": name,
        "entry_point": entry_point,
        "parameters": parameters
    }
    content_str = json.dumps(content, sort_keys=True)
    return hashlib.sha256(content_str.encode()).hexdigest()
```

**Design Decision: Index on Node vs Relationship**

The `index` property is placed on the **node** (not the relationship) for pragmatic reasons:

**Pros:**
- Index is visible in diff UI (node properties are exposed in `old_props`/`new_props`)
- Works with existing diff API (no code changes required)
- Simpler querying (index is directly on the node)

**Cons:**
- Less semantic purity (index is contextual, not inherent)
- Less deduplication (same signature at different index = different nodes)

**Rationale:**
- Syscall numbers are very stable in Linux (ABI compatibility guarantee)
- Index is critical information users want to see in diffs
- Current diff API doesn't expose relationship properties (limitation documented in architecture.md)
- Deduplication benefit is minimal (same signature at different index is rare)

**Future Refactoring Path:**
If deduplication becomes important, we can introduce a `SyscallSignature` node:
```cypher
Syscall {index} -[:HAS_SIGNATURE]-> SyscallSignature {name, entry_point, parameters}
```

## Relationship Definitions

### HAS_SYSCALL_TABLE

Connects a kernel Blob to its syscall tables.

**Relationship Properties:**
- `name: String!` - Table identifier for HashMap key uniqueness
  - Linux: `"x64"` or `"x86"` (architecture)
  - Windows: `"nt"` or `"win32k"` (syscall source)

**Cardinality:**
- Linux vmlinuz: 1→2 (one blob, two tables: x64 + x86)
- Windows ntoskrnl.exe: 1→1 (one blob, one NT table)
- Windows win32k.sys: 1→1 (one blob, one Win32k table)

**Constraint:**
- Relationship names must be unique per parent Blob (enforced by diff algorithm HashMap)

### HAS_SYSCALL

Connects a SyscallTable to its syscall entries.

**Relationship Properties:**
- `name: String!` - Syscall name (e.g., `"read"`) - HashMap key
- `index: Int!` - Syscall number (for display, not part of HashMap key)

**Cardinality:**
- One SyscallTable → Many Syscalls (typically 300-400 syscalls per table)

**Constraint:**
- Relationship names (syscall names) must be unique per SyscallTable
- This is naturally enforced: each syscall has a unique name within a table

## Examples

### Linux: vmlinuz with Both Architectures

```cypher
// The vmlinuz blob
CREATE (vmlinuz:Blob {hash: "abc123..."})

// x64 syscall table
CREATE (table_x64:SyscallTable {
  hash: "def456...",
  arch: "X64"
})

// x86 compat syscall table
CREATE (table_x86:SyscallTable {
  hash: "ghi789...",
  arch: "X86"
})

// Connect blob to tables
CREATE (vmlinuz)-[:HAS_SYSCALL_TABLE {name: "x64"}]->(table_x64)
CREATE (vmlinuz)-[:HAS_SYSCALL_TABLE {name: "x86"}]->(table_x86)

// x64 syscall entries
CREATE (sc_read_x64:Syscall {
  hash: "jkl012...",
  index: 0,
  name: "read",
  entry_point: "sys_read",
  parameters: ["unsigned int fd", "char *buf", "size_t count"]
})

CREATE (sc_write_x64:Syscall {
  hash: "mno345...",
  index: 1,
  name: "write",
  entry_point: "sys_write",
  parameters: ["unsigned int fd", "const char *buf", "size_t count"]
})

// x86 compat syscall entries (different entry points)
CREATE (sc_read_x86:Syscall {
  hash: "pqr678...",
  index: 3,
  name: "read",
  entry_point: "compat_sys_read",
  parameters: ["unsigned int fd", "char *buf", "size_t count"]
})

// Connect table to syscalls
CREATE (table_x64)-[:HAS_SYSCALL {name: "read", index: 0}]->(sc_read_x64)
CREATE (table_x64)-[:HAS_SYSCALL {name: "write", index: 1}]->(sc_write_x64)
CREATE (table_x86)-[:HAS_SYSCALL {name: "read", index: 3}]->(sc_read_x86)
```

### Windows: NT and Win32k SSDTs

```cypher
// NT kernel blob
CREATE (ntoskrnl:Blob {hash: "win_abc..."})

// Win32k kernel blob
CREATE (win32k:Blob {hash: "win_def..."})

// NT syscall table (x64 only)
CREATE (table_nt:SyscallTable {
  hash: "nt_hash...",
  arch: "X64"
})

// Win32k syscall table (x64 only)
CREATE (table_win32k:SyscallTable {
  hash: "w32k_hash...",
  arch: "X64"
})

// Connect blobs to tables
CREATE (ntoskrnl)-[:HAS_SYSCALL_TABLE {name: "nt"}]->(table_nt)
CREATE (win32k)-[:HAS_SYSCALL_TABLE {name: "win32k"}]->(table_win32k)

// NT syscalls
CREATE (nt_open:Syscall {
  hash: "nt_open_hash...",
  index: 51,
  name: "NtOpenFile",
  entry_point: "NtOpenFile",
  parameters: ["PHANDLE FileHandle", "ACCESS_MASK DesiredAccess", "..."]
})

// Win32k syscalls
CREATE (w32k_create:Syscall {
  hash: "w32k_create_hash...",
  index: 4156,
  name: "NtUserCreateWindowEx",
  entry_point: "NtUserCreateWindowEx",
  parameters: ["DWORD dwExStyle", "PUNICODE_STRING lpClassName", "..."]
})

// Connect tables to syscalls
CREATE (table_nt)-[:HAS_SYSCALL {name: "NtOpenFile", index: 51}]->(nt_open)
CREATE (table_win32k)-[:HAS_SYSCALL {name: "NtUserCreateWindowEx", index: 4156}]->(w32k_create)
```

## Diff Algorithm Integration

### Relationship Name Uniqueness

The diff algorithm requires unique relationship `name` properties per parent node for HashMap-based comparison.

**SyscallTable level:**
- Blob → SyscallTable: Names are unique (`"x64"`, `"x86"`, `"nt"`, `"win32k"`)
- ✅ No collisions possible

**Syscall level:**
- SyscallTable → Syscall: Names are syscall names (`"read"`, `"write"`, etc.)
- ✅ Syscall names are unique within a table (by definition)

### Recursive Diffing

When comparing two kernel versions:

1. **Blob level:** Diff finds changed vmlinuz blob
2. **Recurse into SyscallTable:** Diff compares x64 and x86 tables separately
3. **Recurse into Syscall:** Diff identifies added/removed/modified syscalls

**Example diff output:**
```
MOD  /boot/vmlinuz-5.15.0
  MOD  x64
    NEW  read (index: 0)
    MOD  write (index: 1)  [parameters changed]
    DEL  oldcall (index: 999)
  MOD  x86
    NEW  read (index: 3)
```

### Path Display in Frontend

With current diff API:
- Path shows: `/boot/vmlinuz/x64/read`
- Index is visible in `new_props.properties.index`
- Frontend can display: `"Syscall #0: read"`

## Future Enhancements

### 1. JSON Path Approach (Not Yet Implemented)

**Problem:** Current diff API only exposes the relationship `name` property in the path. The `index` property is lost.

**Future Solution:** Serialize all relationship properties as JSON:

```
Current path: /boot/vmlinuz/x64/read
JSON path:    /boot/vmlinuz/{"name":"x64"}/{"name":"read","index":0}
```

**Implementation Requirements:**
- Modify `TreeDiffRecursiveProcedure.java` to serialize relationship properties to JSON
- Use JSON string as HashMap key (deterministic serialization with sorted keys)
- Frontend parses JSON segments to extract both name and index
- No GraphQL schema changes needed

**Benefits:**
- Generic solution for all relationship properties
- Self-contained path segments
- Backward compatible

### 2. Deduplication Refactoring

If syscall signature reuse becomes important, introduce a `SyscallSignature` node:

```cypher
(SyscallTable)-[:HAS_SYSCALL {name: "read", index: 0}]->(Syscall {index: 0})
(Syscall)-[:HAS_SIGNATURE]->(SyscallSignature {
  hash: "sig_hash...",
  name: "read",
  entry_point: "sys_read",
  parameters: [...]
})
```

This enables:
- Same signature at different indices shares `SyscallSignature` node
- Tracks syscall renumbering across kernel versions
- Better deduplication for storage efficiency

## GraphQL Schema Integration

The syscall data model will be added to `graphql-api/type-defs.graphql` in the [graphql-api](https://github.com/OSWatcher/graphql-api) repository:

```graphql
type SyscallTable implements Hashable {
  hash: String! @unique
  arch: String!
  syscalls: [Syscall!]! @relationship(
    type: "HAS_SYSCALL"
    direction: OUT
    properties: "HasSyscallRel"
  )
  blob: Blob! @relationship(
    type: "HAS_SYSCALL_TABLE"
    direction: IN
    properties: "HasNameRel"
  )
}

type Syscall implements Hashable {
  hash: String! @unique
  index: Int!
  name: String!
  entry_point: String!
  parameters: [String!]!
  table: SyscallTable! @relationship(
    type: "HAS_SYSCALL"
    direction: IN
    properties: "HasSyscallRel"
  )
}

type HasSyscallRel @relationshipProperties {
  name: String!
  index: Int!
}

# Add to Blob type:
type Blob implements Hashable {
  # ... existing fields ...
  has_syscall_tables: [SyscallTable!]! @relationship(
    type: "HAS_SYSCALL_TABLE"
    direction: OUT
    properties: "HasNameRel"
  )
}
```

## References

- Diff algorithm implementation: `oswatcher-procedures` repo — `src/main/java/io/oswatcher/TreeDiffRecursiveProcedure.java`
- Plugin implementation: [`plugins/plugins/syscalls.py`](../plugins/plugins/syscalls.py)

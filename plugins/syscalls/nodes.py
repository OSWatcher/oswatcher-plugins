"""Domain Node and MerkleNode classes for syscall data transformation."""

from __future__ import annotations

import hashlib
import json
from typing import Iterator, List, Optional

from attrs import define, field
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleLabel, MerkleNode, Node
from neogit.core.visitor import VisitedNode


@define(auto_attribs=True)
class SyscallNode(Node):
    """Represents a single syscall entry (leaf node)."""

    name: str
    index: int
    entry_point: str
    parameters: Optional[List[str]]

    def iter_child_nodes(self) -> Iterator[Node]:
        """Syscall is a leaf node with no children."""
        return iter([])


@define(auto_attribs=True)
class SyscallTableNode(Node):
    """Represents a syscall table for an architecture (internal node)."""

    architecture: str  # e.g., "lief._lief.ELF.ARCH.x86_64"
    syscalls: List[dict]  # Raw syscall data from extraction

    def iter_child_nodes(self) -> Iterator[Node]:
        """Yield SyscallNode for each syscall in the table."""
        for sc in self.syscalls:
            yield SyscallNode(
                name=sc["name"],
                index=sc["index"],
                entry_point=sc["entry_point"],
                parameters=sc.get("parameters"),
            )


@define(auto_attribs=True)
class SyscallMerkleNode(MerkleNode):
    """Merkle node for a syscall (content-addressed)."""

    name: str = field(kw_only=True)
    index: int = field(kw_only=True)
    entry_point: str = field(kw_only=True)
    parameters: str = field(kw_only=True)  # JSON serialized


@define(auto_attribs=True)
class SyscallTableMerkleNode(MerkleNode):
    """Merkle node for a syscall table (content-addressed)."""

    architecture: str = field(kw_only=True)


class SyscallsMerkleVisitor(MerkleVisitor):
    """Visitor for computing merkle hashes of syscall nodes."""

    def visit_SyscallNode(self, node: SyscallNode, hash_obj: hashlib._Hash, *args, **kwargs):
        """Visit a syscall leaf node and compute its hash.

        Hash includes: index + name + entry_point + parameters (sorted)
        """
        # Serialize parameters to JSON (sorted for determinism)
        params_json = json.dumps(node.parameters, sort_keys=True) if node.parameters else ""

        # Hash: index + name + entry_point + parameters
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

    def visit_SyscallTableNode(self, node: SyscallTableNode, hash_obj: hashlib._Hash, *args, **kwargs):
        """Visit a syscall table and aggregate child hashes.

        Hash includes: all syscall hashes (sorted by index) + architecture
        """
        children = {}

        # Sort by index for deterministic ordering
        sorted_syscalls = sorted(node.iter_child_nodes(), key=lambda s: s.index)

        for syscall_node in sorted_syscalls:
            # Recursively visit child
            visited = self.visit(syscall_node, *args, **kwargs)
            merkle_child = visited.return_value

            # Accumulate: syscall_name + hash
            data = f"{syscall_node.name}{merkle_child.hash}\n".encode()
            hash_obj.update(data)

            children[syscall_node.name] = merkle_child

        # Add table metadata
        hash_obj.update(f"{node.architecture}".encode())

        merkle_node = SyscallTableMerkleNode(
            hash=hash_obj.hexdigest(),
            children=children,
            label=MerkleLabel.Tree,  # Internal node
            architecture=node.architecture,
        )
        return VisitedNode(node, merkle_node)

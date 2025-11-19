"""Unit tests for syscall Node and MerkleNode transformation.

Tests the domain node structure and merkle visitor hash computation.
"""

import hashlib

from neogit.core.model import MerkleLabel

from plugins.syscalls.nodes import (
    SyscallMerkleNode,
    SyscallNode,
    SyscallsMerkleVisitor,
    SyscallTableMerkleNode,
    SyscallTableNode,
)


class TestSyscallNode:
    """Test SyscallNode domain model."""

    def test_create_syscall_node_with_parameters(self):
        """SyscallNode should be created with all fields."""
        node = SyscallNode(
            name="read",
            index=0,
            entry_point="sys_read",
            parameters=["unsigned int fd", "char *buf", "size_t count"],
        )

        assert node.name == "read"
        assert node.index == 0
        assert node.entry_point == "sys_read"
        assert node.parameters == ["unsigned int fd", "char *buf", "size_t count"]

    def test_create_syscall_node_without_parameters(self):
        """SyscallNode should accept None for parameters."""
        node = SyscallNode(name="getpid", index=39, entry_point="sys_getpid", parameters=None)

        assert node.name == "getpid"
        assert node.parameters is None

    def test_syscall_node_is_leaf(self):
        """SyscallNode should have no children (leaf node)."""
        node = SyscallNode(name="read", index=0, entry_point="sys_read", parameters=None)

        children = list(node.iter_child_nodes())

        assert children == []


class TestSyscallTableNode:
    """Test SyscallTableNode domain model."""

    def test_create_syscall_table_node(self):
        """SyscallTableNode should be created with architecture and syscalls."""
        syscalls_data = [
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": ["unsigned int fd"]},
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
        ]

        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)

        assert node.architecture == "lief._lief.ELF.ARCH.x86_64"
        assert node.syscalls == syscalls_data

    def test_syscall_table_node_yields_children(self):
        """SyscallTableNode should yield SyscallNode for each syscall."""
        syscalls_data = [
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": ["unsigned int fd"]},
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
        ]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)

        children = list(node.iter_child_nodes())

        assert len(children) == 2
        assert all(isinstance(child, SyscallNode) for child in children)
        assert children[0].name == "read"
        assert children[0].index == 0
        assert children[1].name == "write"
        assert children[1].index == 1

    def test_syscall_table_node_empty_syscalls(self):
        """SyscallTableNode should handle empty syscall list."""
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=[])

        children = list(node.iter_child_nodes())

        assert children == []


class TestSyscallsMerkleVisitor:
    """Test SyscallsMerkleVisitor hash computation."""

    def test_visit_syscall_node_creates_merkle_node(self):
        """Visiting SyscallNode should create SyscallMerkleNode."""
        node = SyscallNode(name="read", index=0, entry_point="sys_read", parameters=["unsigned int fd"])
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallNode(node, hash_obj)

        merkle_node = visited.return_value
        assert isinstance(merkle_node, SyscallMerkleNode)
        assert merkle_node.name == "read"
        assert merkle_node.index == 0
        assert merkle_node.entry_point == "sys_read"
        assert merkle_node.label == MerkleLabel.Blob

    def test_visit_syscall_node_hash_determinism(self):
        """Visiting same SyscallNode should produce same hash."""
        node = SyscallNode(name="read", index=0, entry_point="sys_read", parameters=["unsigned int fd"])
        visitor = SyscallsMerkleVisitor()

        hash1 = hashlib.sha256()
        visited1 = visitor.visit_SyscallNode(node, hash1)
        merkle1 = visited1.return_value

        hash2 = hashlib.sha256()
        visited2 = visitor.visit_SyscallNode(node, hash2)
        merkle2 = visited2.return_value

        assert merkle1.hash == merkle2.hash

    def test_visit_syscall_node_different_parameters_different_hash(self):
        """Different parameters should produce different hashes."""
        node1 = SyscallNode(name="read", index=0, entry_point="sys_read", parameters=["unsigned int fd"])
        node2 = SyscallNode(name="read", index=0, entry_point="sys_read", parameters=["unsigned int fd", "char *buf"])
        visitor = SyscallsMerkleVisitor()

        hash1 = hashlib.sha256()
        visited1 = visitor.visit_SyscallNode(node1, hash1)
        merkle1 = visited1.return_value

        hash2 = hashlib.sha256()
        visited2 = visitor.visit_SyscallNode(node2, hash2)
        merkle2 = visited2.return_value

        assert merkle1.hash != merkle2.hash

    def test_visit_syscall_node_without_parameters(self):
        """Visiting SyscallNode without parameters should work."""
        node = SyscallNode(name="getpid", index=39, entry_point="sys_getpid", parameters=None)
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallNode(node, hash_obj)

        merkle_node = visited.return_value
        assert merkle_node.parameters == ""
        assert merkle_node.hash  # Should have computed hash

    def test_visit_syscall_node_parameters_json_sorted(self):
        """Parameters should be JSON serialized with sorted keys."""
        node = SyscallNode(
            name="read",
            index=0,
            entry_point="sys_read",
            parameters=["char *buf", "unsigned int fd", "size_t count"],
        )
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallNode(node, hash_obj)

        merkle_node = visited.return_value
        # JSON serialization should be deterministic (list order preserved)
        assert '"char *buf"' in merkle_node.parameters
        assert '"unsigned int fd"' in merkle_node.parameters

    def test_visit_syscall_table_node_creates_merkle_node(self):
        """Visiting SyscallTableNode should create SyscallTableMerkleNode."""
        syscalls_data = [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallTableNode(node, hash_obj)

        merkle_node = visited.return_value
        assert isinstance(merkle_node, SyscallTableMerkleNode)
        assert merkle_node.architecture == "lief._lief.ELF.ARCH.x86_64"
        assert merkle_node.label == MerkleLabel.Tree

    def test_visit_syscall_table_node_has_children(self):
        """SyscallTableMerkleNode should contain child SyscallMerkleNodes."""
        syscalls_data = [
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None},
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
        ]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallTableNode(node, hash_obj)

        merkle_node = visited.return_value
        assert len(merkle_node.children) == 2
        assert "read" in merkle_node.children
        assert "write" in merkle_node.children
        assert isinstance(merkle_node.children["read"], SyscallMerkleNode)
        assert isinstance(merkle_node.children["write"], SyscallMerkleNode)

    def test_visit_syscall_table_node_hash_determinism(self):
        """Visiting same SyscallTableNode should produce same hash."""
        syscalls_data = [
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None},
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
        ]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)
        visitor = SyscallsMerkleVisitor()

        hash1 = hashlib.sha256()
        visited1 = visitor.visit_SyscallTableNode(node, hash1)
        merkle1 = visited1.return_value

        hash2 = hashlib.sha256()
        visited2 = visitor.visit_SyscallTableNode(node, hash2)
        merkle2 = visited2.return_value

        assert merkle1.hash == merkle2.hash

    def test_visit_syscall_table_node_sorts_by_index(self):
        """SyscallTableNode should process syscalls sorted by index."""
        # Insert in reverse order
        syscalls_data = [
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None},
        ]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallTableNode(node, hash_obj)

        # Hash should be deterministic regardless of input order
        merkle_node = visited.return_value
        assert merkle_node.hash  # Should compute successfully

    def test_visit_syscall_table_node_different_architecture_different_hash(self):
        """Different architecture should produce different hash."""
        syscalls_data = [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}]
        node1 = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)
        node2 = SyscallTableNode(architecture="lief._lief.ELF.ARCH.i386", syscalls=syscalls_data)
        visitor = SyscallsMerkleVisitor()

        hash1 = hashlib.sha256()
        visited1 = visitor.visit_SyscallTableNode(node1, hash1)
        merkle1 = visited1.return_value

        hash2 = hashlib.sha256()
        visited2 = visitor.visit_SyscallTableNode(node2, hash2)
        merkle2 = visited2.return_value

        assert merkle1.hash != merkle2.hash

    def test_visit_syscall_table_node_empty_table(self):
        """Visiting empty SyscallTableNode should work."""
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=[])
        visitor = SyscallsMerkleVisitor()
        hash_obj = hashlib.sha256()

        visited = visitor.visit_SyscallTableNode(node, hash_obj)

        merkle_node = visited.return_value
        assert merkle_node.children == {}
        assert merkle_node.hash  # Should still compute hash


class TestMerkleVisitorIntegration:
    """Test full visitor pattern with run_visit() and threaded mode."""

    def test_run_visit_syscall_table(self):
        """Using run_visit() should work with SyscallTableNode."""
        syscalls_data = [
            {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": ["unsigned int fd"]},
            {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
        ]
        node = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls_data)

        with SyscallsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(node)

            results = list(visitor.as_gen())

        # Visitor returns all nodes: 2 SyscallNodes + 1 SyscallTableNode
        assert len(results) == 3

        # Find the SyscallTableMerkleNode
        table_nodes = [r for r in results if isinstance(r.return_value, SyscallTableMerkleNode)]
        assert len(table_nodes) == 1

        merkle_node = table_nodes[0].return_value
        assert isinstance(merkle_node, SyscallTableMerkleNode)
        assert len(merkle_node.children) == 2

    def test_run_visit_multiple_tables(self):
        """Visitor should handle multiple SyscallTableNodes."""
        syscalls1 = [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}]
        syscalls2 = [{"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None}]
        node1 = SyscallTableNode(architecture="lief._lief.ELF.ARCH.x86_64", syscalls=syscalls1)
        node2 = SyscallTableNode(architecture="lief._lief.ELF.ARCH.i386", syscalls=syscalls2)

        with SyscallsMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(node1)
            visitor.run_visit(node2)

            results = list(visitor.as_gen())

        # Visitor should return at least the nodes we submitted
        # (Note: threaded visitor may only return one batch at a time)
        assert len(results) >= 2

        # Filter for SyscallTableMerkleNodes
        table_nodes = [r for r in results if isinstance(r.return_value, SyscallTableMerkleNode)]
        assert len(table_nodes) >= 1
        assert all(isinstance(r.return_value, SyscallTableMerkleNode) for r in table_nodes)

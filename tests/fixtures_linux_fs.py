"""Fixtures for creating Linux filesystem structures in Neo4j for testing.

Reuses neogit's MerkleNode and Tree.create_from_merkle_node_neomodel() to build
test filesystems without real filesystem I/O.
"""

from datetime import datetime

import pytest
from neogit.core.model.merkle import MerkleLabel, MerkleNode
from neogit.model.neo import Commit

# SHA1 of empty string - useful default
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def make_hash(name: str) -> str:
    """Generate a valid SHA1 hash from a name for testing."""
    import hashlib

    return hashlib.sha1(name.encode()).hexdigest()


@pytest.fixture
def make_linux_fs(clean_neo4j_db):
    """Factory for creating Linux filesystem structures in Neo4j from MerkleNode specs.

    Uses neogit's existing MerkleNode domain model and Tree.create_from_merkle_node_neomodel()
    to build Neo4j graphs without real filesystem I/O.

    Example:
        def test_plugin(make_linux_fs):
            # Build filesystem declaratively using MerkleNode
            boot = MerkleNode(hash="boot_hash", label=MerkleLabel.Tree, children={
                "vmlinuz-5.15.0-91-generic": MerkleNode("blob1", MerkleLabel.Blob),
                "vmlinuz-6.1.0-13-amd64": MerkleNode("blob2", MerkleLabel.Blob),
            })

            root = MerkleNode(hash="root_hash", label=MerkleLabel.Tree, children={
                "boot": boot,
            })

            commit = make_linux_fs(root)
            # Test your plugin...
    """

    def build_tree_recursive(merkle_node: MerkleNode):
        """Recursively build Tree/Blob nodes from MerkleNode."""
        from neogit.model.merkle import Blob, Tree

        # Create Tree node (workaround: set both hash and sha1sum to same value)
        # TODO: Remove sha1sum once neogit deprecates it
        tree = Tree(hash=merkle_node.hash, sha1sum=merkle_node.hash).save()

        # Create children blobs
        for name, child_node in merkle_node.children.items():
            if child_node.label == MerkleLabel.Blob:
                blob = Blob(hash=child_node.hash, sha1sum=child_node.hash).save()
                tree.children_blob.connect(blob, {"name": name})
            elif child_node.label == MerkleLabel.Tree:
                child_tree = build_tree_recursive(child_node)
                tree.children_tree.connect(child_tree, {"name": name})

        return tree

    def create_filesystem(
        root_merkle: MerkleNode,
        create_commit: bool = True,
        commit_message: str = "Test snapshot",
        commit_hash: str = "test_commit_hash",
    ):
        """Create filesystem in Neo4j from MerkleNode specification.

        Args:
            root_merkle: MerkleNode representing root filesystem tree
            create_commit: Whether to create and attach a Commit node
            commit_message: Message for the commit
            commit_hash: Hash for the commit node

        Returns:
            Commit node if create_commit=True, else root Tree node
        """
        # Build tree structure recursively
        root_tree = build_tree_recursive(root_merkle)

        if create_commit:
            commit = Commit(
                name="test_snapshot",
                date=datetime.now(),
                hash=make_hash(commit_hash),
                sha1sum=make_hash(commit_hash),
                message=commit_message,
            ).save()
            commit.filesystem.connect(root_tree)
            return commit

        return root_tree

    return create_filesystem


@pytest.fixture
def minimal_linux_fs(make_linux_fs):
    """Create a minimal Linux filesystem with /boot and one kernel.

    Convenience fixture for common test scenarios.
    Returns a Commit node.
    """
    # Build /boot with one vmlinuz file
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={"vmlinuz-5.15.0-91-generic": MerkleNode(make_hash("vmlinuz_blob"), MerkleLabel.Blob)},
    )

    # Build root with /boot
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})

    return make_linux_fs(root, commit_message="Minimal test filesystem")


@pytest.fixture
def multi_kernel_fs(make_linux_fs):
    """Create filesystem with multiple kernel versions in /boot.

    Returns a Commit node with 3 kernels + other boot files.
    """
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={
            "vmlinuz-5.15.0-91-generic": MerkleNode(make_hash("vmlinuz_515"), MerkleLabel.Blob),
            "vmlinuz-6.1.0-13-amd64": MerkleNode(make_hash("vmlinuz_61"), MerkleLabel.Blob),
            "vmlinuz-6.5.0-25-generic": MerkleNode(make_hash("vmlinuz_65"), MerkleLabel.Blob),
            "config-5.15.0-91-generic": MerkleNode(make_hash("config_515"), MerkleLabel.Blob),  # Should be ignored
            "initrd.img-5.15.0-91-generic": MerkleNode(make_hash("initrd_515"), MerkleLabel.Blob),  # Should be ignored
        },
    )

    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})

    return make_linux_fs(root, commit_message="Multi-kernel filesystem")


@pytest.fixture
def empty_fs(make_linux_fs):
    """Create an empty filesystem (just root, no children).

    Useful for testing edge cases and error handling.
    """
    root = MerkleNode(hash=EMPTY_SHA1, label=MerkleLabel.Tree, children={})

    return make_linux_fs(root, commit_message="Empty filesystem")


@pytest.fixture
def no_boot_fs(make_linux_fs):
    """Create filesystem without /boot directory.

    Tests plugin behavior when /boot is missing.
    """
    etc = MerkleNode(
        hash=make_hash("etc"),
        label=MerkleLabel.Tree,
        children={"hostname": MerkleNode(make_hash("hostname_blob"), MerkleLabel.Blob)},
    )

    usr_bin = MerkleNode(
        hash=make_hash("usr_bin"),
        label=MerkleLabel.Tree,
        children={"bash": MerkleNode(make_hash("bash_blob"), MerkleLabel.Blob)},
    )

    usr = MerkleNode(hash=make_hash("usr"), label=MerkleLabel.Tree, children={"bin": usr_bin})

    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"etc": etc, "usr": usr})

    return make_linux_fs(root, commit_message="Filesystem without /boot")


@pytest.fixture
def boot_as_file_fs(make_linux_fs):
    """Create filesystem where /boot is a file, not a directory.

    Edge case: tests plugin error handling when /boot exists but is the wrong type.
    """
    root = MerkleNode(
        hash=make_hash("root"),
        label=MerkleLabel.Tree,
        children={
            "boot": MerkleNode(make_hash("boot_file_blob"), MerkleLabel.Blob),  # /boot is a file!
            "etc": MerkleNode(make_hash("etc"), MerkleLabel.Tree, children={}),
        },
    )

    return make_linux_fs(root, commit_message="/boot as file edge case")

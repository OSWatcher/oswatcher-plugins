"""Test that linux_fs fixtures create correct Neo4j structures."""

from pathlib import PurePath

import pytest
from neogit.core.model.merkle import MerkleLabel, MerkleNode
from neogit.model.merkle import Blob, Tree


@pytest.mark.integration
def test_minimal_linux_fs_creates_structure(minimal_linux_fs):
    """Verify minimal_linux_fs fixture creates expected graph."""
    # Should have a commit
    assert minimal_linux_fs.message == "Minimal test filesystem"

    # Should have filesystem attached
    root = minimal_linux_fs.filesystem[0]
    assert isinstance(root, Tree)

    # Should have /boot directory
    boot = root.get_child_at_path(PurePath("/boot"))
    assert isinstance(boot, Tree)

    # Should have vmlinuz file in /boot
    children = list(boot.iter_children())
    assert len(children) == 1
    name, node = children[0]
    assert name == "vmlinuz-5.15.0-91-generic"
    assert isinstance(node, Blob)


@pytest.mark.integration
def test_multi_kernel_fs_creates_multiple_files(multi_kernel_fs):
    """Verify multi_kernel_fs fixture creates multiple kernel files."""
    root = multi_kernel_fs.filesystem[0]
    boot = root.get_child_at_path(PurePath("/boot"))

    # Should have 5 files in /boot
    children = list(boot.iter_children())
    assert len(children) == 5

    filenames = [name for name, node in children]
    assert "vmlinuz-5.15.0-91-generic" in filenames
    assert "vmlinuz-6.1.0-13-amd64" in filenames
    assert "vmlinuz-6.5.0-25-generic" in filenames


@pytest.mark.integration
def test_empty_fs_has_no_children(empty_fs):
    """Verify empty_fs fixture creates empty root."""
    root = empty_fs.filesystem[0]

    # Root should have no children
    children = list(root.iter_children())
    assert len(children) == 0


@pytest.mark.integration
def test_no_boot_fs_missing_boot(no_boot_fs):
    """Verify no_boot_fs fixture doesn't have /boot."""
    root = no_boot_fs.filesystem[0]

    # Should raise FileNotFoundError when accessing /boot
    with pytest.raises(FileNotFoundError):
        root.get_child_at_path(PurePath("/boot"))

    # But should have /etc
    etc = root.get_child_at_path(PurePath("/etc"))
    assert isinstance(etc, Tree)


@pytest.mark.integration
def test_make_linux_fs_custom_structure(make_linux_fs):
    """Test creating custom filesystem with make_linux_fs."""
    import hashlib

    def make_hash(name):
        return hashlib.sha1(name.encode()).hexdigest()

    # Build custom structure
    etc = MerkleNode(
        hash=make_hash("etc"),
        label=MerkleLabel.Tree,
        children={
            "hostname": MerkleNode(make_hash("hostname"), MerkleLabel.Blob),
            "fstab": MerkleNode(make_hash("fstab"), MerkleLabel.Blob),
        },
    )

    root = MerkleNode(hash=make_hash("custom_root"), label=MerkleLabel.Tree, children={"etc": etc})

    commit = make_linux_fs(root, commit_message="Custom test")

    # Verify structure
    assert commit.message == "Custom test"
    root_tree = commit.filesystem[0]
    etc_tree = root_tree.get_child_at_path(PurePath("/etc"))

    children = list(etc_tree.iter_children())
    assert len(children) == 2

    filenames = [name for name, node in children]
    assert "hostname" in filenames
    assert "fstab" in filenames

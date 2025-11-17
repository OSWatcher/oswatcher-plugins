"""Test filesystem navigation functions for syscall plugin.

Tests public functions - no private method testing, no implementation smell.
"""

import pytest
from neogit.core.model.merkle import MerkleLabel, MerkleNode

from plugins.syscalls.filesystem import find_kernel_versions, get_boot_directory
from tests.fixtures_linux_fs import make_hash


@pytest.mark.integration
def test_get_boot_directory_found(minimal_linux_fs):
    """get_boot_directory should find /boot when it exists."""
    root = minimal_linux_fs.filesystem[0]

    boot = get_boot_directory(root)

    assert boot is not None


@pytest.mark.integration
def test_get_boot_directory_missing(no_boot_fs):
    """get_boot_directory should return None when /boot missing."""
    root = no_boot_fs.filesystem[0]

    boot = get_boot_directory(root)

    assert boot is None


@pytest.mark.integration
def test_get_boot_directory_is_file(boot_as_file_fs):
    """get_boot_directory should return None when /boot is a file."""
    root = boot_as_file_fs.filesystem[0]

    boot = get_boot_directory(root)

    assert boot is None


@pytest.mark.integration
def test_get_boot_directory_empty_root(empty_fs):
    """get_boot_directory should return None on empty filesystem."""
    root = empty_fs.filesystem[0]

    boot = get_boot_directory(root)

    assert boot is None


@pytest.mark.integration
def test_find_kernel_versions_single(minimal_linux_fs):
    """find_kernel_versions should find single kernel."""
    root = minimal_linux_fs.filesystem[0]
    boot = get_boot_directory(root)

    versions = find_kernel_versions(boot)

    assert versions == ["v5.15"]


@pytest.mark.integration
def test_find_kernel_versions_multiple(multi_kernel_fs):
    """find_kernel_versions should find all kernels and sort them."""
    root = multi_kernel_fs.filesystem[0]
    boot = get_boot_directory(root)

    versions = find_kernel_versions(boot)

    assert versions == ["v5.15", "v6.1", "v6.5"]


@pytest.mark.integration
def test_find_kernel_versions_ignores_non_kernel_files(make_linux_fs):
    """find_kernel_versions should ignore config/initrd files."""
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={
            "vmlinuz-5.15.0-91-generic": MerkleNode(make_hash("vm"), MerkleLabel.Blob),
            "config-5.15.0-91-generic": MerkleNode(make_hash("cfg"), MerkleLabel.Blob),
            "initrd.img-5.15.0": MerkleNode(make_hash("initrd"), MerkleLabel.Blob),
            "System.map-5.15.0": MerkleNode(make_hash("sysmap"), MerkleLabel.Blob),
        },
    )
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    versions = find_kernel_versions(boot_tree)

    assert versions == ["v5.15"]


@pytest.mark.integration
def test_find_kernel_versions_deduplicates(make_linux_fs):
    """find_kernel_versions should deduplicate same kernel versions."""
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={
            "vmlinuz-5.15.0-91-generic": MerkleNode(make_hash("vm1"), MerkleLabel.Blob),
            "vmlinuz-5.15.0-92-generic": MerkleNode(make_hash("vm2"), MerkleLabel.Blob),
            "vmlinuz-5.15.1-generic": MerkleNode(make_hash("vm3"), MerkleLabel.Blob),
        },
    )
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    versions = find_kernel_versions(boot_tree)

    # All three are v5.15, should deduplicate to one
    assert versions == ["v5.15"]


@pytest.mark.integration
def test_find_kernel_versions_returns_sorted(make_linux_fs):
    """find_kernel_versions should return versions in sorted order."""
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={
            "vmlinuz-6.5.0-25-generic": MerkleNode(make_hash("vm1"), MerkleLabel.Blob),
            "vmlinuz-5.15.0-91-generic": MerkleNode(make_hash("vm2"), MerkleLabel.Blob),
            "vmlinuz-6.1.0-13-amd64": MerkleNode(make_hash("vm3"), MerkleLabel.Blob),
        },
    )
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    versions = find_kernel_versions(boot_tree)

    # Should be sorted regardless of insertion order
    assert versions == ["v5.15", "v6.1", "v6.5"]


@pytest.mark.integration
def test_find_kernel_versions_empty_boot(make_linux_fs):
    """find_kernel_versions should return empty list when /boot is empty."""
    boot = MerkleNode(hash=make_hash("boot"), label=MerkleLabel.Tree, children={})
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    versions = find_kernel_versions(boot_tree)

    assert versions == []


@pytest.mark.integration
def test_find_kernel_versions_only_non_vmlinuz_files(make_linux_fs):
    """find_kernel_versions should return empty list when no vmlinuz files."""
    boot = MerkleNode(
        hash=make_hash("boot"),
        label=MerkleLabel.Tree,
        children={
            "config-5.15.0": MerkleNode(make_hash("cfg"), MerkleLabel.Blob),
            "initrd.img": MerkleNode(make_hash("initrd"), MerkleLabel.Blob),
            "grub": MerkleNode(make_hash("grub"), MerkleLabel.Tree, children={}),
        },
    )
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    versions = find_kernel_versions(boot_tree)

    assert versions == []

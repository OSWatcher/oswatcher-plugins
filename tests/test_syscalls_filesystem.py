"""Test filesystem navigation functions for syscall plugin.

Tests public functions - no private method testing, no implementation smell.
"""

import tempfile
from contextlib import contextmanager
from unittest.mock import Mock

import pytest
from neogit.core.model.merkle import MerkleLabel, MerkleNode

from plugins.syscalls.filesystem import find_kernel_versions, get_boot_directory
from tests.fixtures_linux_fs import make_hash


@pytest.fixture
def mock_plugin():
    """Mock plugin with downloaded_file() context manager that provides fake x86_64 ELF files."""
    plugin = Mock()
    plugin.logger = Mock()

    @contextmanager
    def mock_downloaded_file(blob_hash):
        # Create a minimal valid x86_64 ELF file for lief to parse
        # ELF Header structure for x86-64:
        # - ELF magic: 0x7f, 'E', 'L', 'F'
        # - EI_CLASS: 2 (64-bit)
        # - EI_DATA: 1 (little-endian)
        # - EI_VERSION: 1
        # - e_machine: 0x3e (x86-64)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as f:
            # ELF header (minimum for lief to parse)
            elf_header = bytearray(64)
            elf_header[0:4] = b"\x7fELF"  # ELF magic
            elf_header[4] = 2  # EI_CLASS: 64-bit
            elf_header[5] = 1  # EI_DATA: little-endian
            elf_header[6] = 1  # EI_VERSION
            # e_machine at offset 18-19 (little-endian)
            elf_header[18:20] = (0x3E).to_bytes(2, byteorder="little")  # x86-64

            f.write(bytes(elf_header))
            f.flush()
            yield f.name

    plugin.downloaded_file = mock_downloaded_file
    return plugin


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
def test_find_kernel_versions_single(minimal_linux_fs, mock_plugin):
    """find_kernel_versions should find single kernel."""
    root = minimal_linux_fs.filesystem[0]
    boot = get_boot_directory(root)

    kernel_infos = find_kernel_versions(boot, mock_plugin)

    assert len(kernel_infos) == 1
    assert kernel_infos[0].version == "v5.15"
    assert kernel_infos[0].filename == "vmlinuz-5.15.0-91-generic"
    assert kernel_infos[0].blob_hash  # Has a hash
    assert kernel_infos[0].architecture == "lief._lief.ELF.ARCH.x86_64"  # lief enum string


@pytest.mark.integration
def test_find_kernel_versions_multiple(multi_kernel_fs, mock_plugin):
    """find_kernel_versions should find all kernels and sort them."""
    root = multi_kernel_fs.filesystem[0]
    boot = get_boot_directory(root)

    kernel_infos = find_kernel_versions(boot, mock_plugin)

    assert len(kernel_infos) == 3
    versions = [k.version for k in kernel_infos]
    assert versions == ["v5.15", "v6.1", "v6.5"]
    # All should have architecture detected
    assert all(k.architecture == "lief._lief.ELF.ARCH.x86_64" for k in kernel_infos)


@pytest.mark.integration
def test_find_kernel_versions_ignores_non_kernel_files(make_linux_fs, mock_plugin):
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
    kernel_infos = find_kernel_versions(boot_tree, mock_plugin)

    assert len(kernel_infos) == 1
    assert kernel_infos[0].version == "v5.15"


@pytest.mark.integration
def test_find_kernel_versions_deduplicates(make_linux_fs, mock_plugin):
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
    kernel_infos = find_kernel_versions(boot_tree, mock_plugin)

    # All three are v5.15, should deduplicate to one
    assert len(kernel_infos) == 1
    assert kernel_infos[0].version == "v5.15"


@pytest.mark.integration
def test_find_kernel_versions_returns_sorted(make_linux_fs, mock_plugin):
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
    kernel_infos = find_kernel_versions(boot_tree, mock_plugin)

    # Should be sorted regardless of insertion order
    versions = [k.version for k in kernel_infos]
    assert versions == ["v5.15", "v6.1", "v6.5"]


@pytest.mark.integration
def test_find_kernel_versions_empty_boot(make_linux_fs, mock_plugin):
    """find_kernel_versions should return empty list when /boot is empty."""
    boot = MerkleNode(hash=make_hash("boot"), label=MerkleLabel.Tree, children={})
    root = MerkleNode(hash=make_hash("root"), label=MerkleLabel.Tree, children={"boot": boot})
    commit = make_linux_fs(root)

    boot_tree = get_boot_directory(commit.filesystem[0])
    kernel_infos = find_kernel_versions(boot_tree, mock_plugin)

    assert kernel_infos == []


@pytest.mark.integration
def test_find_kernel_versions_only_non_vmlinuz_files(make_linux_fs, mock_plugin):
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
    kernel_infos = find_kernel_versions(boot_tree, mock_plugin)

    assert kernel_infos == []

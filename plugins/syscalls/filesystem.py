"""Filesystem navigation utilities for Linux kernel analysis."""

from dataclasses import dataclass
from pathlib import PurePath
from typing import TYPE_CHECKING, List, Optional

import lief
from neogit.model.merkle import Blob, Tree

if TYPE_CHECKING:
    from plugins.types import AbstractPlugin


@dataclass(frozen=True)
class KernelInfo:
    """Information about a kernel found in /boot directory."""

    version: str  # e.g., "v5.15"
    blob_hash: str  # Neo4j Blob hash
    filename: str  # e.g., "vmlinuz-5.15.0-91-generic"
    architecture: str  # e.g., "x86_64", "AARCH64" (from lief enum)


def detect_kernel_arch(vmlinuz_path: str) -> str:
    """Detect kernel architecture using lief parser.

    Handles both raw ELF kernels (vmlinux) and compressed vmlinuz files
    with an EFI boot stub (PE header).

    Args:
        vmlinuz_path: Path to vmlinuz file (local filesystem)

    Returns:
        Architecture string from lief enum (e.g., "ARCH.x86_64", "MACHINE_TYPES.AMD64")

    Raises:
        ValueError: If file cannot be parsed or architecture cannot be determined
    """
    binary = lief.parse(vmlinuz_path)

    if binary is None:
        raise ValueError(f"Failed to parse {vmlinuz_path}")

    # Raw ELF kernel (e.g., vmlinux)
    if isinstance(binary, lief.ELF.Binary):
        return str(binary.header.machine_type)

    # Compressed vmlinuz with EFI boot stub (PE header)
    if isinstance(binary, lief.PE.Binary):
        return str(binary.header.machine)

    raise ValueError(f"Unsupported binary format: {vmlinuz_path}")


def get_boot_directory(root: Tree) -> Optional[Tree]:
    """Navigate to /boot directory.

    Args:
        root: Root filesystem tree

    Returns:
        Tree node for /boot directory, or None if not found or not a directory
    """
    try:
        boot = root.get_child_at_path(PurePath("/boot"))
        if isinstance(boot, Tree):
            return boot
    except FileNotFoundError:
        pass
    return None


def find_kernel_versions(boot: Tree, plugin: "AbstractPlugin") -> List[KernelInfo]:
    """Find kernel versions from /boot directory contents.

    Args:
        boot: /boot directory tree
        plugin: Plugin instance (for downloading blobs)

    Returns:
        Sorted list of unique kernel information (version, hash, filename, architecture)
    """
    from plugins.syscalls.kernel_parser import parse_kernel_version

    kernel_infos = []
    seen_versions = set()

    for name, child in boot.iter_children():
        if not isinstance(child, Blob) or not name.startswith("vmlinuz-"):
            continue

        try:
            version = parse_kernel_version(name)

            # Skip duplicate versions (multiple builds of same version)
            if version in seen_versions:
                continue

            # Download blob and detect architecture
            with plugin.downloaded_file(child.hash) as vmlinuz_path:
                try:
                    architecture = detect_kernel_arch(vmlinuz_path)
                except ValueError as e:
                    plugin.logger.warning(f"Failed to detect architecture for {name}: {e}")
                    continue

            kernel_info = KernelInfo(
                version=version,
                blob_hash=child.hash,
                filename=name,
                architecture=architecture,
            )
            kernel_infos.append(kernel_info)
            seen_versions.add(version)

        except ValueError:
            # Skip files that don't parse as valid kernel versions
            continue

    # Sort by version for deterministic ordering
    return sorted(kernel_infos, key=lambda k: k.version)

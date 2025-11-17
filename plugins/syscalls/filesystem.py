"""Filesystem navigation utilities for Linux kernel analysis."""

from pathlib import PurePath
from typing import List, Optional

from neogit.model.merkle import Tree


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


def find_kernel_versions(boot: Tree) -> List[str]:
    """Find kernel versions from /boot directory contents.

    Args:
        boot: /boot directory tree

    Returns:
        Sorted list of unique kernel versions (e.g., ['v5.15', 'v6.1'])
    """
    from plugins.syscalls.kernel_parser import parse_kernel_version

    versions = []
    for name, child in boot.iter_children():
        if name.startswith("vmlinuz-"):
            try:
                version = parse_kernel_version(name)
                versions.append(version)
            except ValueError:
                # Skip files that don't parse as valid kernel versions
                continue

    return sorted(set(versions))

"""Kernel version and syscall parsing from boot filenames and headers."""

import re
from dataclasses import dataclass

# Compiled regex pattern for kernel filename parsing
# Pattern: vmlinuz-{major}.{minor}.{patch}-{build}-{flavor}
KERNEL_VERSION_PATTERN = re.compile(r'^vmlinuz-(\d+)\.(\d+)\..*')


@dataclass(frozen=True)
class SyscallIndex:
    """Represents a syscall with its name and index."""
    name: str
    index: int


def parse_kernel_version(filename: str) -> str:
    """Parse kernel version from vmlinuz filename.
    
    Args:
        filename: Boot filename like 'vmlinuz-5.15.0-91-generic'
        
    Returns:
        Kernel version like 'v5.15'
        
    Raises:
        ValueError: If filename format is invalid
    """
    match = KERNEL_VERSION_PATTERN.match(filename)
    if not match:
        raise ValueError(f"Invalid kernel filename format: {filename}")
    
    major, minor = match.groups()
    return f"v{major}.{minor}"
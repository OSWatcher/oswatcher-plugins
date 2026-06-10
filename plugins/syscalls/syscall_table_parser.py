# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

"""Syscall table parsing from syscall_64.tbl format."""

import re
from typing import Optional

from .kernel_parser import SyscallIndex

# Compiled regex pattern for syscall table line parsing
# Pattern: <number> <abi> <name> [<entry_point>] [optional_fields...]
SYSCALL_TABLE_PATTERN = re.compile(r"^(\d+)\s+(common|64|x32)\s+(\w+)(?:\s+(\w+))?")


def parse_syscall_table_line(line: str) -> Optional[SyscallIndex]:
    """Parse a single line from syscall_64.tbl format.

    Args:
        line: Table line like '0\tcommon\tread\tsys_read'

    Returns:
        SyscallIndex instance or None for filtered/invalid lines

    Raises:
        ValueError: If line format is invalid but not filtered
    """
    line = line.strip()

    # Filter out empty lines and comments
    if not line or line.startswith("#"):
        return None

    match = SYSCALL_TABLE_PATTERN.match(line)
    if not match:
        raise ValueError(f"Invalid syscall table line format: {line}")

    number_str, abi, name, entry_point = match.groups()

    # Some syscalls don't have entry points defined (like uselib)
    if entry_point is None:
        entry_point = f"sys_{name}"

    # Filter out x32 ABI for 64-bit focus
    if abi == "x32":
        return None

    index = int(number_str)
    return SyscallIndex(name=name, index=index)

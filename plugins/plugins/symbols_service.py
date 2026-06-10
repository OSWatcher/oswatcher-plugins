# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

"""Pure functions for symbols plugin business logic."""

import hashlib
from pathlib import PurePath
from typing import Dict, List, Tuple


def filter_valid_filenames(
    blob_results: List[Tuple[PurePath, str]], allowed_filenames: List[str]
) -> List[Tuple[PurePath, str]]:
    """Filter blob results to only include allowed filenames.

    This is a pure function with no side effects.

    Args:
        blob_results: List of (path, blob_hash) tuples
        allowed_filenames: List of allowed filenames to keep

    Returns:
        Filtered list of (path, blob_hash) tuples
    """
    return [(path, blob_hash) for path, blob_hash in blob_results if path.name in allowed_filenames]


def parse_symbols_from_json(symbols_dict: Dict) -> List[Dict[str, str]]:
    """Parse symbols from PDB JSON, filtering mangled names.

    This is a pure function with no side effects.

    Filters out symbols starting with '?' or '$' (compiler-generated).

    Args:
        symbols_dict: Dictionary mapping symbol names to symbol data

    Returns:
        List of symbol dictionaries with name, address, and hash fields
    """
    entries = []
    for sym, value in sorted(symbols_dict.items()):
        # Skip mangled/compiler symbols
        if sym.startswith("?") or sym.startswith("$"):
            continue

        address = str(value["address"])
        entries.append({"name": sym, "address": address, "hash": hashlib.sha1(address.encode()).hexdigest()})

    return entries

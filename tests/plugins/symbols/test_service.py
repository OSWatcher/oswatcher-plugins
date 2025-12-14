"""Unit tests for symbols_service.py pure functions."""

import hashlib
from pathlib import PurePath

from plugins.plugins.symbols_service import filter_valid_filenames, parse_symbols_from_json


class TestFilterValidFilenames:
    """Tests for filter_valid_filenames function."""

    def test_filters_allowed_filenames(self):
        """Should only include blobs with allowed filenames."""
        blob_results = [
            (PurePath("/Windows/System32/ntoskrnl.exe"), "hash1"),
            (PurePath("/Windows/System32/user32.dll"), "hash2"),
            (PurePath("/Windows/System32/kernel32.dll"), "hash3"),
        ]
        allowed = ["ntoskrnl.exe", "kernel32.dll"]

        result = filter_valid_filenames(blob_results, allowed)

        assert len(result) == 2
        assert result[0] == (PurePath("/Windows/System32/ntoskrnl.exe"), "hash1")
        assert result[1] == (PurePath("/Windows/System32/kernel32.dll"), "hash3")

    def test_empty_input_returns_empty(self):
        """Should return empty list for empty input."""
        result = filter_valid_filenames([], ["ntoskrnl.exe"])
        assert result == []

    def test_no_matches_returns_empty(self):
        """Should return empty list when no filenames match."""
        blob_results = [(PurePath("/foo/bar.dll"), "hash1")]
        result = filter_valid_filenames(blob_results, ["ntoskrnl.exe"])
        assert result == []

    def test_preserves_order(self):
        """Should preserve input order."""
        blob_results = [
            (PurePath("/b/kernel32.dll"), "hash2"),
            (PurePath("/a/ntoskrnl.exe"), "hash1"),
            (PurePath("/c/ntdll.dll"), "hash3"),
        ]
        allowed = ["ntoskrnl.exe", "kernel32.dll", "ntdll.dll"]

        result = filter_valid_filenames(blob_results, allowed)

        assert len(result) == 3
        assert result[0][0].name == "kernel32.dll"
        assert result[1][0].name == "ntoskrnl.exe"
        assert result[2][0].name == "ntdll.dll"

    def test_case_sensitive_matching(self):
        """Should perform case-sensitive filename matching."""
        blob_results = [
            (PurePath("/Windows/System32/NTOSKRNL.EXE"), "hash1"),
            (PurePath("/Windows/System32/ntoskrnl.exe"), "hash2"),
        ]
        allowed = ["ntoskrnl.exe"]

        result = filter_valid_filenames(blob_results, allowed)

        assert len(result) == 1
        assert result[0][0].name == "ntoskrnl.exe"


class TestParseSymbolsFromJson:
    """Tests for parse_symbols_from_json function."""

    def test_parses_valid_symbols(self):
        """Should parse valid symbol entries."""
        symbols = {
            "NtCreateFile": {"address": 0x1000},
            "KeInitializeThread": {"address": 0x2000},
        }

        result = parse_symbols_from_json(symbols)

        assert len(result) == 2
        # Results are sorted by name
        assert result[0]["name"] == "KeInitializeThread"
        assert result[0]["address"] == "8192"  # 0x2000
        assert result[1]["name"] == "NtCreateFile"
        assert result[1]["address"] == "4096"  # 0x1000

    def test_filters_mangled_names_with_question_mark(self):
        """Should filter out symbols starting with '?'."""
        symbols = {
            "NtCreateFile": {"address": 0x1000},
            "?mangled_name": {"address": 0x2000},
        }

        result = parse_symbols_from_json(symbols)

        assert len(result) == 1
        assert result[0]["name"] == "NtCreateFile"

    def test_filters_compiler_symbols_with_dollar_sign(self):
        """Should filter out symbols starting with '$'."""
        symbols = {
            "NtCreateFile": {"address": 0x1000},
            "$compiler_symbol": {"address": 0x3000},
        }

        result = parse_symbols_from_json(symbols)

        assert len(result) == 1
        assert result[0]["name"] == "NtCreateFile"

    def test_filters_both_mangled_and_compiler_symbols(self):
        """Should filter out both '?' and '$' prefixed symbols."""
        symbols = {
            "ValidSymbol": {"address": 0x1000},
            "?mangled": {"address": 0x2000},
            "$compiler": {"address": 0x3000},
            "AnotherValid": {"address": 0x4000},
        }

        result = parse_symbols_from_json(symbols)

        assert len(result) == 2
        assert result[0]["name"] == "AnotherValid"
        assert result[1]["name"] == "ValidSymbol"

    def test_empty_dict_returns_empty_list(self):
        """Should return empty list for empty input."""
        result = parse_symbols_from_json({})
        assert result == []

    def test_hash_is_sha1_of_address(self):
        """Should compute SHA1 hash of address string."""
        symbols = {"TestSymbol": {"address": 0x1234}}

        result = parse_symbols_from_json(symbols)

        expected_hash = hashlib.sha1("4660".encode()).hexdigest()
        assert result[0]["hash"] == expected_hash

    def test_address_stored_as_string(self):
        """Should store address as string (for Neo4j compatibility)."""
        symbols = {"Sym1": {"address": 0xFFFFFFFFFFFFFFFF}}  # Large 64-bit value

        result = parse_symbols_from_json(symbols)

        assert isinstance(result[0]["address"], str)
        assert result[0]["address"] == str(0xFFFFFFFFFFFFFFFF)

    def test_sorted_output(self):
        """Should return symbols sorted by name."""
        symbols = {
            "ZebraFunc": {"address": 0x3000},
            "AlphaFunc": {"address": 0x1000},
            "MidFunc": {"address": 0x2000},
        }

        result = parse_symbols_from_json(symbols)

        assert result[0]["name"] == "AlphaFunc"
        assert result[1]["name"] == "MidFunc"
        assert result[2]["name"] == "ZebraFunc"

    def test_result_structure(self):
        """Should return dictionaries with expected keys."""
        symbols = {"TestFunc": {"address": 0x5000}}

        result = parse_symbols_from_json(symbols)

        assert len(result) == 1
        symbol = result[0]
        assert "name" in symbol
        assert "address" in symbol
        assert "hash" in symbol
        assert len(symbol) == 3  # Only these 3 keys

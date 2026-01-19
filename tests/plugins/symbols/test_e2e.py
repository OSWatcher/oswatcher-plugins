"""
End-to-end tests for the symbols plugin.

These tests validate the complete pipeline using real PDB data from Microsoft's symbol server.
Network tests require internet connectivity to download PDBs (~30MB on first run).
Subsequent runs use volatility's built-in caching (~/.cache/volatility3/).
"""

from unittest.mock import MagicMock, patch

import lief
import pytest
from neogit.core.model.merkle import MerkleLabel, MerkleNode
from neogit.service.neogit import cypher_query_with_backoff

from plugins.plugins.symbols import SymbolsPlugin
from tests.fixtures_linux_fs import make_hash


@pytest.fixture
def simple_neogit_init(clean_neo4j_db):
    """Simple neogit instance without parametrization - uses FakeObjectStorage and default workers."""
    from neogit.object_storage import FakeObjectStorage, TSObjectStorage
    from neogit.service import Neogit

    ts_obj = TSObjectStorage(FakeObjectStorage, None)
    neogit = Neogit(ts_obj)
    return neogit


@pytest.mark.integration
@patch("plugins.plugins.symbols.lief.parse")
def test_symbols_plugin_real_pdb(
    mock_lief_parse,
    make_linux_fs,
    simple_neogit_init,
    tmp_path,
):
    """
    E2E test with real PDB download from Microsoft symbol server.

    This test validates the complete symbols plugin pipeline:
    1. Create filesystem with ntoskrnl.exe blob
    2. Add PE MIME type to blob
    3. Mock lief to return CodeView debug info
    4. Let volatility download and parse real PDB (uses cache)
    5. Verify symbols and structs inserted into Neo4j

    Network: Required on first run to download PDB (~30MB, ~30-60s).
             Subsequent runs use volatility's cache (~5-10s).
    """
    # Step 1: Create filesystem with ntoskrnl.exe blob
    ntoskrnl_blob = MerkleNode(
        hash=make_hash("ntoskrnl_blob"),
        label=MerkleLabel.Blob,
        children={},
    )

    system32 = MerkleNode(
        hash=make_hash("system32"),
        label=MerkleLabel.Tree,
        children={"ntoskrnl.exe": ntoskrnl_blob},
    )

    windows = MerkleNode(
        hash=make_hash("windows"),
        label=MerkleLabel.Tree,
        children={"System32": system32},
    )

    root = MerkleNode(
        hash=make_hash("root"),
        label=MerkleLabel.Tree,
        children={"Windows": windows},
    )

    # Create commit
    commit = make_linux_fs(root, commit_message="Windows filesystem with ntoskrnl")

    # Step 2: Add PE MIME type to blob (simulates FileTypePlugin)
    query = """
    MERGE (m:MimeType {mime: $mime_type})
    WITH m
    MATCH (b:Blob {hash: $blob_hash})
    MERGE (b)-[:HAS_MIME_TYPE]->(m)
    """
    cypher_query_with_backoff(
        query,
        {"blob_hash": make_hash("ntoskrnl_blob"), "mime_type": "application/vnd.microsoft.portable-executable"},
    )

    # Step 3: Mock lief.parse() to return CodeView debug info
    # Using real Windows 10 21H2 ntoskrnl.exe metadata
    # GUID: 55678bc384f099b6ed05e9e39046924a converted to signature bytes
    # Format: parts 1-3 are little-endian, part 4 is big-endian
    signature_bytes = [
        0xC3,
        0x8B,
        0x67,
        0x55,  # part1 (reversed): 55678bc3
        0xF0,
        0x84,  # part2 (reversed): 84f0
        0xB6,
        0x99,  # part3 (reversed): 99b6
        0xED,
        0x05,
        0xE9,
        0xE3,
        0x90,
        0x46,
        0x92,
        0x4A,  # part4 (not reversed)
    ]

    mock_pe = MagicMock()
    mock_debug = MagicMock()
    mock_debug.type = lief.PE.Debug.TYPES.CODEVIEW
    mock_debug.signature = signature_bytes
    mock_debug.age = 1
    mock_debug.filename = "ntkrnlmp.pdb"

    mock_pe.debug = [mock_debug]
    mock_lief_parse.return_value = mock_pe

    # Step 4: Mock file download and run plugin
    fake_pe_path = tmp_path / "ntoskrnl.exe"
    fake_pe_path.write_bytes(b"MZ\x90\x00")  # Minimal PE header

    plugin = SymbolsPlugin()
    plugin.neogit = simple_neogit_init

    # ensure constraints
    with plugin.neogit.db.transaction:
        plugin.ensure_constraints()

    with patch.object(plugin, "downloaded_file") as mock_download:
        mock_download.return_value.__enter__.return_value = fake_pe_path
        mock_download.return_value.__exit__.return_value = None

        # Run plugin - volatility will download real PDB from symbol server
        plugin.run(commit)

    # Step 5: Verify data inserted into Neo4j

    # Verify symbols were inserted
    query = "MATCH (s:Symbol) RETURN count(s) as count"
    rows, _ = cypher_query_with_backoff(query, {})
    symbol_count = rows[0][0] if rows else 0
    assert symbol_count > 0, "No symbols found in database"

    # Verify real Windows kernel symbols exist
    # Query for symbol names associated with the blob
    query = """
    MATCH (b:Blob {hash: $blob_hash})-[r:HAS_SYMBOL]->(s:Symbol)
    RETURN r.name as symbol_name
    """
    rows, _ = cypher_query_with_backoff(query, {"blob_hash": make_hash("ntoskrnl_blob")})
    symbol_names = {row[0] for row in rows}

    # Check for well-known kernel functions (should exist in real ntkrnlmp.pdb)
    expected_symbols = ["NtCreateFile", "NtOpenFile", "KeInitializeApc"]
    found_symbols = [name for name in expected_symbols if name in symbol_names]
    assert (
        len(found_symbols) > 0
    ), f"Expected to find kernel symbols like {expected_symbols}, found symbols: {list(symbol_names)[:20]}"

    # Verify structs were inserted
    query = "MATCH (s:Struct) RETURN count(s) as count"
    rows, _ = cypher_query_with_backoff(query, {})
    struct_count = rows[0][0] if rows else 0
    assert struct_count > 0, "No structs found in database"

    # Check for well-known kernel structs (should exist in real ntkrnlmp.pdb)
    query = """
    MATCH (b:Blob {hash: $blob_hash})-[r:HAS_STRUCT]->(s:Struct)
    RETURN r.name as struct_name
    """
    rows, _ = cypher_query_with_backoff(query, {"blob_hash": make_hash("ntoskrnl_blob")})
    struct_names = {row[0] for row in rows}

    expected_structs = ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY"]
    found_structs = [name for name in expected_structs if name in struct_names]
    assert (
        len(found_structs) > 0
    ), f"Expected to find kernel structs like {expected_structs}, found structs: {list(struct_names)[:20]}"

    # Verify blob has relationships to symbols and structs
    assert len(symbol_names) > 0, "Blob should have symbol relationships"
    assert len(struct_names) > 0, "Blob should have struct relationships"

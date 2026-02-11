"""Repository layer for symbols plugin Neo4j operations."""

from pathlib import PurePath
from typing import Dict, List, Tuple

from neogit.service.neogit import cypher_query_with_backoff


class SymbolsRepository:
    """Handles Neo4j database operations for symbols plugin."""

    def __init__(self, neogit):
        """Initialize repository with neogit service.

        Args:
            neogit: Neogit service instance for database access
        """
        self.neogit = neogit

    def query_pe_blobs(self, root_hash: str, mime_type: str) -> List[Tuple[PurePath, str]]:
        """Query for PE file blobs matching MIME type.

        Args:
            root_hash: Hash of the root Tree node
            mime_type: MIME type to filter by

        Returns:
            List of (file_path, blob_hash) tuples
        """
        query = """
        MATCH path = (r:Tree {hash: $root_hash})-[:HAS_CHILD_TREE|HAS_CHILD_BLOB*]->(b:Blob)
        WHERE EXISTS {
                MATCH (b)-[:HAS_MIME_TYPE]->(m:MimeType)
                WHERE m.mime = $mime_type
            }
        RETURN [rel IN relationships(path) | rel.name] AS parts, b.hash
        """
        rows, _ = self.neogit.db.cypher_query(query, {"mime_type": mime_type, "root_hash": root_hash})
        return [(PurePath(*row[0]), row[1]) for row in rows]

    def insert_symbols(self, blob_hash: str, param_list: List[Dict]) -> None:
        """Insert symbols into Neo4j.

        Args:
            blob_hash: Hash of the PE file blob
            param_list: List of dicts with hash, address, and symbol name key
                (`sym_name` or `name`)
        """
        query = """
        MATCH (b:Blob {hash: $blob_hash})
        WITH b
        UNWIND $unwind as p
        MERGE (s:Symbol {hash: p.hash, address: p.address})
        MERGE (b)-[:HAS_SYMBOL {name: coalesce(p.sym_name, p.name)}]->(s)
        """
        cypher_query_with_backoff(query, {"blob_hash": blob_hash, "unwind": param_list})

    def insert_struct(self, blob_hash: str, struct_node, unwind_param: List[Dict]) -> None:
        """Insert Windows struct definition into Neo4j.

        Args:
            blob_hash: Hash of the PE file blob
            struct_node: StructMerkleNode with hash, size, kind, name
            unwind_param: List of field dicts with hash, name, offset, data_type
        """
        query = """
        MERGE (s:Struct {hash: $hash, size: $size, kind: $kind})
        WITH s
        UNWIND $unwind_param as x
        MERGE (f:StructField {hash: x.hash, offset: x.offset, data_type: x.data_type})
        MERGE (s)-[:HAS_FIELD {name: x.name}]->(f)
        WITH s
        MATCH (b:Blob {hash: $blob_hash})
        WITH b, s
        MERGE (b)-[:HAS_STRUCT {name: $name}]->(s)
        """
        cypher_query_with_backoff(
            query,
            {
                "blob_hash": blob_hash,
                "unwind_param": unwind_param,
                "hash": struct_node.hash,
                "name": struct_node.name,
                "size": struct_node.size,
                "kind": struct_node.kind.name,
            },
        )

    def insert_data_type(self, node) -> None:
        """Insert Windows data type into Neo4j.

        Args:
            node: DataTypeMerkleNode with type metadata
        """
        query = """
        MERGE (d:DataType {hash: $hash})  // Ensure 'hash' uniquely identifies 'DataType'
        ON CREATE SET
            d.type = CASE WHEN $type IS NOT NULL THEN $type END,
            d.name = CASE WHEN $name IS NOT NULL THEN $name END,
            d.array_counter = CASE WHEN $array_counter IS NOT NULL THEN $array_counter END,
            d.bit_position = CASE WHEN $bit_position IS NOT NULL THEN $bit_position END,
            d.bit_length = CASE WHEN $bit_length IS NOT NULL THEN $bit_length END
        ON MATCH SET
            d.type = CASE WHEN $type IS NOT NULL THEN $type END,
            d.name = CASE WHEN $name IS NOT NULL THEN $name END,
            d.array_counter = CASE WHEN $array_counter IS NOT NULL THEN $array_counter END,
            d.bit_position = CASE WHEN $bit_position IS NOT NULL THEN $bit_position END,
            d.bit_length = CASE WHEN $bit_length IS NOT NULL THEN $bit_length END
        WITH d
        UNWIND $children AS child
        MERGE (c:DataType {hash: child.hash})  // Assuming 'hash' is unique for child nodes too
        ON CREATE SET
            c.type = CASE WHEN child.type IS NOT NULL THEN child.type END,
            c.name = CASE WHEN child.name IS NOT NULL THEN child.name END,
            c.array_counter = CASE WHEN child.array_counter IS NOT NULL THEN child.array_counter END,
            c.bit_position = CASE WHEN child.bit_position IS NOT NULL THEN child.bit_position END,
            c.bit_length = CASE WHEN child.bit_length IS NOT NULL THEN child.bit_length END
        MERGE (d)-[:HAS_DATA_TYPE]->(c)
        """
        children = [
            {
                "hash": x.hash,
                "type": x.kind.name,
                "name": x.name,
                "array_counter": x.array_counter,
                "bit_position": x.bit_position,
                "bit_length": x.bit_length,
            }
            for hash, x in node.children.items()
        ]
        cypher_query_with_backoff(
            query,
            {
                "hash": node.hash,
                "type": node.kind.name,
                "name": node.name,
                "array_counter": node.array_counter,
                "bit_position": node.bit_position,
                "bit_length": node.bit_length,
                "children": children,
            },
        )

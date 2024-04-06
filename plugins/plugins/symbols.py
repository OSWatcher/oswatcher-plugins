from __future__ import annotations

import hashlib
import json
from binascii import hexlify
from enum import Enum, auto
from pathlib import Path
from typing import Dict, Generator, Optional
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import lief
from attrs import define, field
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleLabel, MerkleNode, Node
from neogit.core.visitor import VisitedNode
from neogit.model.neo import Commit
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver

from plugins.types import AbstractPlugin


# enums
@define(auto_attribs=True)
class EnumMemberNode(Node):
    name: str = field()
    value: int = field()


@define(auto_attribs=True)
class EnumNode(Node):
    enum_name: str = field()
    enum_data: Dict = field()

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        for name, value in self.enum_data["constants"].items():
            yield EnumMemberNode(name=name, value=value)


@define(auto_attribs=True)
class EnumMemberMerkleNode(MerkleNode):
    """represents an enum member in the graph"""

    name: str = field(kw_only=True)
    value: int = field(kw_only=True)


@define(auto_attribs=True)
class EnumMerkleNode(MerkleNode):
    name: str = field(kw_only=True)


# User Types (structs)


class FieldKindType(Enum):
    Base = auto()
    Pointer = auto()
    Enum = auto()
    Array = auto()
    Struct = auto()
    Union = auto()
    Bitfield = auto()


class UserTypeKindType(Enum):
    Struct = auto()
    Union = auto()


@define(auto_attribs=True)
class WinStructNode(Node):
    name: str
    struct_data: Dict
    # either struct or union
    kind: UserTypeKindType = field(init=False)
    size: int = field(init=False)

    def __attrs_post_init__(self):
        self.size = self.struct_data["size"]
        self.kind = UserTypeKindType[self.struct_data["kind"].capitalize()]

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        # iterate on every field
        for field_name, field_data in self.struct_data["fields"].items():
            field_node = WinStructFieldNode(name=field_name, field_data=field_data)
            yield field_node


@define(auto_attribs=True)
class WinStructFieldNode(Node):
    name: str = field()
    field_data: Dict = field()
    offset: int = field(init=False)
    type: Dict = field(init=False)
    kind: FieldKindType = field(init=False)
    # if array
    array_counter: Optional[int] = field(init=False)
    # if bitfield
    bit_length: Optional[int] = field(init=False)
    bit_position: Optional[int] = field(init=False)
    # if pointer or bitfield or array
    subtype: Optional[Dict] = field(init=False)

    def __attrs_post_init__(self):
        self.offset = self.field_data["offset"]
        self.type = self.field_data["type"]
        self.kind = self.field_data["type"]["kind"]
        match self.kind:
            case FieldKindType.Base | FieldKindType.Enum | FieldKindType.Struct | FieldKindType.Union:
                self.subtype = self.field_data["type"]
            case FieldKindType.Array:
                self.array_counter = self.field_data["type"]["count"]
                self.subtype = self.field_data["type"]["subtype"]
            case FieldKindType.Bitfield:
                self.bit_length = self.field_data["type"]["bit_length"]
                self.bit_position = self.field_data["type"]["bit_position"]
                self.subtype = self.field_data["type"]["type"]
            case FieldKindType.Pointer:
                self.subtype = self.field_data["type"]["subtype"]

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        # construct the subtype node
        yield WinDataTypeNode(self.kind, self.subtype)


@define(auto_attribs=True)
class WinDataTypeNode(Node):
    """Represents basic data types
    - name: unsigned long
    - name: unsigned long long
    - name: void
    - name: int
    - name: void
    """

    kind: FieldKindType = field()
    subtype: Dict = field()


@define(auto_attribs=True)
class WinDataTypeMerkleNode(MerkleNode):
    name: str = field(kw_only=True)


@define(auto_attribs=True)
class WinStructFieldMerkleNode(MerkleNode):
    name: str = field(kw_only=True)
    offset: int = field(kw_only=True)
    type: str = field(kw_only=True)


@define(auto_attribs=True)
class WinStructMerkleNode(MerkleNode):
    name: str = field(kw_only=True)
    size: int = field(kw_only=True)
    kind: UserTypeKindType = field(kw_only=True)


# define the visitor
class SymbolsMerkleVisitor(MerkleVisitor):

    def visit_EnumMemberNode(self, node: EnumMemberNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        hash_obj.update(f"{node.name}{node.value}".encode())
        merkle_node = EnumMemberMerkleNode(
            hash=hash_obj.hexdigest(), label=MerkleLabel.Blob, name=node.name, value=node.value
        )
        return VisitedNode(node, merkle_node)

    def visit_EnumNode(self, node: EnumNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        children = {}
        # ensure sorted by name
        for child in sorted(node.iter_child_nodes(), key=lambda e: e.name):
            # yield children
            visited_node = self.visit(child)
            merkle_node = visited_node.return_value
            data = f"{merkle_node.hash}\n".encode()
            hash_obj.update(data)
            children[child.name] = merkle_node
        # compute final hash
        merkle_node = EnumMerkleNode(
            hash=hash_obj.hexdigest(), children=children, label=MerkleLabel.Tree, name=node.enum_name
        )
        return VisitedNode(node, merkle_node)

    def visit_WinDataTypeNode(self, node: WinDataTypeNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        # TODO
        # match node.kind:
        #     case FieldKindType.Base | FieldKindType.Enum | FieldKindType.Struct | FieldKindType.Union:
        #         data = f"{node.kind.name}{node.subtype['name']}".encode()
        #     case FieldKindType.Pointer:
        #         data = f"{node.subtype['kind']}{node.subtype['name']}"
        pass

    def visit_WinStructFieldNode(
        self, node: WinStructFieldNode, hash_obj: hashlib._Hash, *args, **kwargs
    ) -> VisitedNode:
        # merklize the data type
        # convert type to string for hashing
        # ensure sorted
        type_str = json.dumps(node.type, sort_keys=True)
        hash_obj.update(f"{node.name}{node.offset}{type_str}".encode())
        merkle_node = WinStructFieldMerkleNode(
            hash=hash_obj.hexdigest(), label=MerkleLabel.Blob, name=node.name, offset=node.offset, type=type_str
        )
        return VisitedNode(node, merkle_node)

    def visit_WinStructNode(self, node: WinStructNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        children = {}
        for member in node.iter_child_nodes():
            visited_node = self.visit(member)
            merkle_node = visited_node.return_value
            data = f"{merkle_node.hash}\n".encode()
            hash_obj.update(data)
            children[member.name] = merkle_node
        merkle_node = WinStructMerkleNode(
            hash=hash_obj.hexdigest(),
            children=children,
            label=MerkleLabel.Tree,
            name=node.name,
            size=node.size,
            kind=node.kind,
        )
        return VisitedNode(node, merkle_node)


def parse_code_view(pe_path):
    pe = lief.parse(pe_path)
    for debug_dir in pe.debug:
        if debug_dir.has_code_view:
            code_view = debug_dir.code_view

            part1_bin = code_view.signature[:4]
            part1_bin.reverse()
            part1 = bytearray(part1_bin)
            part2_bin = code_view.signature[4:6]
            part2_bin.reverse()
            part2 = bytearray(part2_bin)
            part3_bin = code_view.signature[6:8]
            part3_bin.reverse()
            part3 = bytearray(part3_bin)
            part4_bin = code_view.signature[8:]
            part4 = bytearray(part4_bin)

            guid = (
                f"{hexlify(part1).decode()}{hexlify(part2).decode()}{hexlify(part3).decode()}{hexlify(part4).decode()}"
            )
            return guid, code_view.age & 0xF, code_view.filename


@define(auto_attribs=True)
class SymbolsPlugin(AbstractPlugin):

    PE_MIME_TYPE = "application/vnd.microsoft.portable-executable"

    def run(self, commit: Commit):
        # identify every PE file Blob
        query = """
        MATCH (b:Blob)-[:HAS_MIME_TYPE]->(m:MimeType)
        WHERE m.mime = $mime_type
        RETURN b.hash
        """
        rows, _ = self.neogit.db.cypher_query(query, {"mime_type": self.__class__.PE_MIME_TYPE})
        for row in rows:
            blob_hash = row[0]
            with self.downloaded_file(blob_hash) as local_file:
                ret = parse_code_view(local_file)
                if not ret:
                    continue
                guid, age, pdb_name = ret
                self.logger.info("GUID: %s, age: %s, PDB: %s", guid, age, pdb_name)
                try:
                    location = self.retrieve_pdb(guid, age, pdb_name)
                except Exception:
                    self.logger.exception("Failed to retrieve PDB on %s", blob_hash)
                    continue
                self.logger.info(location)
                ctx = Context()
                try:
                    j_data = PdbReader(ctx, location).get_json()
                except Exception:
                    self.logger.exception("Failed to parse PDB on %s", blob_hash)
                    continue
                self.parse_pdb_json(blob_hash, j_data)

    def retrieve_pdb(self, guid, age, pdb_name) -> str:
        filename = PdbRetreiver().retreive_pdb(guid + str(age), file_name=pdb_name, progress_callback=None)
        if not filename:
            raise ValueError("PDB file could not be retrieved from the internet")
        url = urllib_parse.urlparse(filename, scheme="file")
        if url.scheme == "file":
            if not Path(filename).exists():
                self.logger.error(f"File {filename} does not exists")
            location = "file:" + urllib_request.pathname2url(Path(filename).absolute())
        else:
            location = filename
        return location

    def parse_pdb_json(self, blob_hash: str, j_pdb: Dict):
        self.parse_enums(blob_hash, j_pdb["enums"])
        self.insert_symbols(blob_hash, j_pdb["symbols"])
        self.parse_users_types(blob_hash, j_pdb["user_types"])

    def parse_enums(self, blob_hash: str, j_pdb: Dict):
        with SymbolsMerkleVisitor() as visitor:
            for enum_name, enum_data in sorted(j_pdb.items()):
                self.logger.info("Enum: %s", enum_name)
                enum_node = EnumNode(enum_name=enum_name, enum_data=enum_data)
                visited_node = visitor.visit(enum_node)
                merkle_node = visited_node.return_value
                assert isinstance(merkle_node, EnumMerkleNode)
                self.insert_enum_cypher(blob_hash, merkle_node)

    def parse_users_types(self, blob_hash: str, j_pdb: Dict):
        with SymbolsMerkleVisitor() as visitor:
            for struct_name, struct_data in sorted(j_pdb.items()):
                self.logger.info("Struct: %s", struct_name)
                struct_node = WinStructNode(name=struct_name, struct_data=struct_data)
                visited_node = visitor.visit(struct_node)
                merkle_node = visited_node.return_value
                assert isinstance(visited_node.return_value, WinStructMerkleNode)
                self.insert_struct_cypher(blob_hash, merkle_node)

    def insert_enum_cypher(self, blob_hash: str, node: EnumMerkleNode):
        query = """
        MERGE (e:Enum {hash: $hash, name: $name})
        WITH e
        UNWIND $unwind_param as x
        MERGE (k:EnumMember {hash: x.hash, name: x.name, value: x.value})
        MERGE (e)-[:HAS_ENUM_MEMBER]->(k)
        WITH e
        MATCH (b:Blob {hash: $blob_hash})
        WITH b, e
        MERGE (b)-[:HAS_ENUM]->(e)
        """
        unwind_param = [
            {"hash": child_node.hash, "name": child_name, "value": child_node.value}
            for child_name, child_node in node.children.items()
        ]
        self.neogit.db.cypher_query(
            query, {"hash": node.hash, "name": node.name, "unwind_param": unwind_param, "blob_hash": blob_hash}
        )

    def insert_struct_cypher(self, blob_hash: str, node: WinStructMerkleNode):
        query = """
        MERGE (s:WinStruct {hash: $hash, name: $name, size: $size, kind: $kind})
        WITH s
        UNWIND $unwind_param as x
        MERGE (f:WinStructField {hash: x.hash, name: x.name, offset: x.offset, type: x.type})
        MERGE (s)-[:HAS_FIELD]->(f)
        WITH s
        MATCH (b:Blob {hash: $blob_hash})
        WITH b, s
        MERGE (b)-[:HAS_STRUCT]->(s)
        """
        unwind_param = [
            {"hash": child_node.hash, "name": child_name, "offset": child_node.offset, "type": child_node.type}
            for child_name, child_node in node.children.items()
        ]
        self.neogit.db.cypher_query(
            query,
            {
                "blob_hash": blob_hash,
                "unwind_param": unwind_param,
                "hash": node.hash,
                "name": node.name,
                "size": node.size,
                "kind": node.kind.name,
            },
        )

    def insert_symbols(self, blob_hash: str, symbols: Dict):
        param_list = []
        for sym, value in sorted(symbols.items()):
            if sym.startswith("?") or sym.startswith("$"):
                continue
            address = value["address"]
            param_list.append(
                {
                    "sym_name": sym,
                    "address": address,
                }
            )
            self.logger.info("Symbol %s (%s)", sym, hex(address))
        query = """
        MATCH (b:Blob {hash: $blob_hash})
        WITH b
        UNWIND $unwind as p
        MERGE (s:Symbol {name: p.sym_name})
        MERGE (b)-[:HAS_SYMBOL {address: p.address}]->(s)
        """
        self.neogit.db.cypher_query(query, {"blob_hash": blob_hash, "unwind": param_list})

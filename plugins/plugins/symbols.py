from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import tempfile
from binascii import hexlify
from contextlib import contextmanager, suppress
from enum import Enum, auto
from pathlib import Path, PurePath
from typing import Dict, Generator, Optional, Tuple
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import lief
import pypeln as pl
from attrs import define, field
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleLabel, MerkleNode, Node
from neogit.core.visitor import VisitedNode
from neogit.model.neo import Commit
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver

from plugins.plugins.symbols_repository import SymbolsRepository
from plugins.plugins.symbols_service import filter_valid_filenames, parse_symbols_from_json
from plugins.types import AbstractPlugin, UniqueConstraint


@contextmanager
def temporary_file_context(path):
    try:
        yield path
    finally:
        os.remove(path)


def return_exceptions(f):
    @functools.wraps(f)
    def wrapped(self, x):
        if isinstance(x, BaseException):
            return x
        try:
            return f(self, x)
        except BaseException as e:
            return e

    return wrapped


# User Types (structs)
class FieldKindType(Enum):
    Base = auto()
    Pointer = auto()
    Function = auto()
    Enum = auto()
    Array = auto()
    Struct = auto()
    Union = auto()
    Bitfield = auto()


class UserTypeKindType(Enum):
    Struct = auto()
    Union = auto()
    Enum = auto()


@define(auto_attribs=True)
class StructNode(Node):
    name: str
    struct_data: Dict
    # either struct, union or enum
    kind: UserTypeKindType = field(init=False)
    size: int = field(init=False)

    def __attrs_post_init__(self):
        self.size = self.struct_data["size"]
        if "constants" in self.struct_data:
            # enum
            self.kind = UserTypeKindType.Enum
        else:
            self.kind = UserTypeKindType[self.struct_data["kind"].capitalize()]

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        if self.kind == UserTypeKindType.Enum:
            for name, value in self.struct_data["constants"].items():
                field_node = StructFieldNode(
                    name=name, field_data={"offset": value, "type": {"kind": FieldKindType.Base.name, "name": "int"}}
                )
                yield field_node
        else:
            # iterate on every field
            for field_name, field_data in self.struct_data["fields"].items():
                field_node = StructFieldNode(name=field_name, field_data=field_data)
                yield field_node


@define(auto_attribs=True)
class StructFieldNode(Node):
    name: str = field()
    field_data: Dict = field()
    offset: int = field(init=False)
    data_type: str = field(init=False)

    def __attrs_post_init__(self):
        self.offset = self.field_data["offset"]
        self.data_type = json.dumps(self.field_data["type"])

    # store data type directly in the field node
    # def iter_child_nodes(self) -> Generator[Node, None, None]:
    #     # construct the subtype node
    #     yield DataTypeNode(data_type=self.field_data["type"])


@define(auto_attribs=True)
class DataTypeNode(Node):
    """Represents basic data types
    - name: unsigned long
    - name: unsigned long long
    - name: void
    - name: int
    - name: void
    """

    data_type: Dict = field()
    kind: FieldKindType = field(init=False)
    # if base, enum, struct, union
    name: Optional[str] = field(init=False)
    # if array
    array_counter: Optional[int] = field(init=False)
    # if bitfield
    bit_length: Optional[int] = field(init=False)
    bit_position: Optional[int] = field(init=False)
    # if pointer or bitfield or array
    subtype: Optional[Dict] = field(init=False)

    def __attrs_post_init__(self):
        self.kind = FieldKindType[self.data_type["kind"].capitalize()]
        match self.kind:
            case FieldKindType.Base | FieldKindType.Enum | FieldKindType.Struct | FieldKindType.Union:
                self.name = self.data_type["name"]
            case FieldKindType.Array:
                self.array_counter = self.data_type["count"]
                self.subtype = self.data_type["subtype"]
            case FieldKindType.Bitfield:
                self.bit_length = self.data_type["bit_length"]
                self.bit_position = self.data_type["bit_position"]
                self.subtype = self.data_type["type"]
            case FieldKindType.Pointer:
                self.subtype = self.data_type["subtype"]
            case FieldKindType.Function:
                self.name = "function"

    def iter_child_nodes(self) -> Generator[Node, None, None]:
        match self.kind:
            case FieldKindType.Array | FieldKindType.Bitfield | FieldKindType.Pointer:
                yield DataTypeNode(data_type=self.subtype)


@define(auto_attribs=True)
class DataTypeMerkleNode(MerkleNode):
    kind: FieldKindType = field(kw_only=True)
    name: Optional[str] = field(default=None, kw_only=True)
    array_counter: Optional[int] = field(default=None, kw_only=True)
    bit_length: Optional[int] = field(default=None, kw_only=True)
    bit_position: Optional[int] = field(default=None, kw_only=True)


@define(auto_attribs=True)
class StructFieldMerkleNode(MerkleNode):
    name: str = field(kw_only=True)
    offset: int = field(kw_only=True)
    data_type: str = field(kw_only=True)


@define(auto_attribs=True)
class StructMerkleNode(MerkleNode):
    name: str = field(kw_only=True)
    size: int = field(kw_only=True)
    kind: UserTypeKindType = field(kw_only=True)


# define the visitor
class SymbolsMerkleVisitor(MerkleVisitor):

    def visit_DataTypeNode(self, node: DataTypeNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        match node.kind:
            case (
                FieldKindType.Base
                | FieldKindType.Enum
                | FieldKindType.Struct
                | FieldKindType.Union
                | FieldKindType.Function
            ):
                hash_obj.update(f"{node.name}".encode())
                merkle_node = DataTypeMerkleNode(
                    hash=hash_obj.hexdigest(), label=MerkleLabel.Blob, kind=node.kind, name=node.name
                )
                return VisitedNode(node, merkle_node)
            case FieldKindType.Array:
                subtype = next(node.iter_child_nodes())
                visited_node = self.visit(subtype)
                merkle_node = visited_node.return_value
                data = f"{merkle_node.hash}-{node.array_counter}\n".encode()
                hash_obj.update(data)
                merkle_node = DataTypeMerkleNode(
                    hash=hash_obj.hexdigest(),
                    label=MerkleLabel.Blob,
                    kind=node.kind,
                    array_counter=node.array_counter,
                    children={merkle_node.name: merkle_node},
                )
                return VisitedNode(node, merkle_node)
            case FieldKindType.Bitfield:
                subtype = next(node.iter_child_nodes())
                visited_node = self.visit(subtype)
                merkle_node = visited_node.return_value
                data = f"{merkle_node.hash}-{node.bit_length}-{node.bit_position}\n".encode()
                hash_obj.update(data)
                merkle_node = DataTypeMerkleNode(
                    hash=hash_obj.hexdigest(),
                    label=MerkleLabel.Blob,
                    kind=node.kind,
                    bit_length=node.bit_length,
                    bit_position=node.bit_position,
                    children={merkle_node.name: merkle_node},
                )
                return VisitedNode(node, merkle_node)
            case FieldKindType.Pointer:
                subtype = next(node.iter_child_nodes())
                visited_node = self.visit(subtype)
                merkle_node = visited_node.return_value
                data = f"{merkle_node.hash}\n".encode()
                hash_obj.update(data)
                merkle_node = DataTypeMerkleNode(
                    hash=hash_obj.hexdigest(),
                    label=MerkleLabel.Blob,
                    kind=node.kind,
                    children={merkle_node.name: merkle_node},
                )
                return VisitedNode(node, merkle_node)

    def visit_StructFieldNode(self, node: StructFieldNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        children = {}
        # for data_type in node.iter_child_nodes():
        #     visited_node = self.visit(data_type)
        #     merkle_node = visited_node.return_value
        #     data = f"{merkle_node.hash}\n".encode()
        #     hash_obj.update(data)
        #     children[merkle_node.hash] = merkle_node
        # merklize the offset and the data type string
        hash_obj.update(f"{node.offset}-{node.data_type}".encode())
        merkle_node = StructFieldMerkleNode(
            hash=hash_obj.hexdigest(),
            label=MerkleLabel.Blob,
            name=node.name,
            offset=node.offset,
            data_type=node.data_type,
            children=children,
        )
        return VisitedNode(node, merkle_node)

    def visit_StructNode(self, node: StructNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        children = {}
        for member in node.iter_child_nodes():
            visited_node = self.visit(member)
            merkle_node = visited_node.return_value
            "field_name-field_hash"
            data = f"{member.name}{merkle_node.hash}\n".encode()
            hash_obj.update(data)
            children[member.name] = merkle_node
        hash_obj.update(f"{node.size}-{node.kind.name}".encode())
        merkle_node = StructMerkleNode(
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
        if debug_dir.type == lief.PE.Debug.TYPES.CODEVIEW:
            part1_bin = debug_dir.signature[:4]
            part1_bin.reverse()
            part1 = bytearray(part1_bin)
            part2_bin = debug_dir.signature[4:6]
            part2_bin.reverse()
            part2 = bytearray(part2_bin)
            part3_bin = debug_dir.signature[6:8]
            part3_bin.reverse()
            part3 = bytearray(part3_bin)
            part4_bin = debug_dir.signature[8:]
            part4 = bytearray(part4_bin)

            guid = (
                f"{hexlify(part1).decode()}{hexlify(part2).decode()}{hexlify(part3).decode()}{hexlify(part4).decode()}"
            )
            return guid, debug_dir.age & 0xF, debug_dir.filename


def _pdb_progress_callback(percentage, description):
    """Progress callback for PDB downloads - must be module-level for multiprocessing pickling.

    Args:
        percentage: Progress percentage (0-100)
        description: Description of current operation
    """
    logging.debug(f"PDB download progress: {percentage: .1f}% - {description}")


def retrieve_pdb(guid, age, pdb_name) -> str:
    logging.debug("Retrieving PDB: %s - GUID: %s - Age: %s", pdb_name, guid, age)
    filename = PdbRetreiver().retreive_pdb(
        guid + str(age), file_name=pdb_name, progress_callback=_pdb_progress_callback
    )
    logging.debug("filename: %s", filename)
    if not filename:
        raise ValueError("PDB file could not be retrieved from the internet")
    url = urllib_parse.urlparse(filename, scheme="file")
    if url.scheme == "file":
        if not Path(filename).exists():
            logging.error(f"File {filename} does not exists")
        location = "file:" + urllib_request.pathname2url(str(Path(filename).absolute()))
    else:
        location = filename
    return location


@define(auto_attribs=True)
class SymbolsPlugin(AbstractPlugin):
    max_workers: int = field(init=False, default=os.cpu_count())
    _repository: SymbolsRepository = field(init=False, default=None)

    PE_MIME_TYPE = "application/vnd.microsoft.portable-executable"
    # only process these filenames for now
    FILTER_FILENAME = ["ntoskrnl.exe", "ntdll.dll", "kernel32.dll"]

    @property
    def repository(self) -> SymbolsRepository:
        """Lazy-initialize repository."""
        if self._repository is None:
            self._repository = SymbolsRepository(self.neogit)
        return self._repository

    def constraints_data(self) -> lief.List[UniqueConstraint]:
        return [
            UniqueConstraint(label="Symbol", property_list=["hash"]),
            UniqueConstraint(label="Struct", property_list=["hash"]),
            UniqueConstraint(label="StructField", property_list=["hash"]),
            UniqueConstraint(label="DataType", property_list=["hash"]),
        ]

    def run(self, commit: Commit):
        # identify every PE file Blob
        fs = commit.filesystem.single()

        # Use repository to query PE blobs
        all_blobs = self.repository.query_pe_blobs(fs.hash, self.__class__.PE_MIME_TYPE)
        blob_results = filter_valid_filenames(all_blobs, self.FILTER_FILENAME)
        stage = pl.process.map(self.stage_parse_code_view, blob_results, workers=4)
        stage = pl.process.map(self.stage_process_pdb, stage, workers=self.max_workers, maxsize=self.max_workers)
        for ret in stage:
            if isinstance(ret, BaseException):
                self.logger.error("Failed to process PDB: %s: %s", type(ret).__name__, ret)
                continue
            blob_hash, pdb_name, tmp_file_path = ret
            try:
                with open(tmp_file_path, "r") as f:
                    j_data = json.load(f)
                self.parse_pdb_json(blob_hash, pdb_name, j_data)
            finally:
                with suppress(FileNotFoundError):
                    os.remove(tmp_file_path)

    @return_exceptions
    def stage_parse_code_view(self, blob_result: Tuple[PurePath, str]) -> Optional[Tuple[str, int, str]]:
        self.logger.info("Processing PE file: %s", blob_result[0])
        blob_hash = blob_result[1]
        with self.downloaded_file(blob_hash) as local_file:
            ret = parse_code_view(local_file)
            if not ret:
                raise ValueError("No CodeView found")
            guid, age, pdb_name = ret
            self.logger.info("Path: %s - PDB: %s - GUID: %s (%s)", blob_result[0], pdb_name, guid, age)
            return blob_hash, *ret

    @return_exceptions
    def stage_process_pdb(self, arg) -> Tuple[str, Path]:
        blob_hash, guid, age, pdb_name = arg
        try:
            location = retrieve_pdb(guid, age, pdb_name)
        except Exception as e:
            self.logger.error("Failed to retrieve PDB for blob %s: %s", blob_hash, e)
            raise ValueError(f"Failed to retrieve PDB {pdb_name} on {blob_hash}") from e
        logging.debug(location)
        ctx = Context()
        try:
            j_data = PdbReader(ctx, location).get_json()
        except Exception as e:
            raise ValueError(f"Failed to parse PDB {pdb_name} on {blob_hash}") from e
        with tempfile.NamedTemporaryFile(delete=False, mode="w+") as tmp_file:
            json.dump(j_data, tmp_file)
            tmp_file.flush()
            self.logger.debug("PDB: %s - JSON file: %s", pdb_name, tmp_file.name)
            return blob_hash, pdb_name, Path(tmp_file.name)

    def parse_pdb_json(self, blob_hash: str, pdb_name: str, j_pdb: Dict):
        self.logger.debug("PDB: %s - Parsing JSON", pdb_name)
        count_enum = self.parse_users_types(blob_hash, j_pdb["enums"])
        count_syms = self.insert_symbols(blob_hash, j_pdb["symbols"])
        count_types = self.parse_users_types(blob_hash, j_pdb["user_types"])
        self.logger.info(
            "PDB: %s - Inserted %d enums, %d symbols, %d user types", pdb_name, count_enum, count_syms, count_types
        )

    def parse_users_types(self, blob_hash: str, j_pdb: Dict) -> int:
        with SymbolsMerkleVisitor(thread=True) as visitor:
            for struct_name, struct_data in sorted(j_pdb.items()):
                self.logger.debug("Struct: %s", struct_name)
                struct_node = StructNode(name=struct_name, struct_data=struct_data)
                visitor.run_visit(struct_node)
                for node in visitor.as_gen():
                    merkle_node = node.return_value
                    if isinstance(merkle_node, DataTypeMerkleNode):
                        self.repository.insert_data_type(merkle_node)
                    if isinstance(merkle_node, StructMerkleNode):
                        unwind_param = [
                            {
                                "hash": child_node.hash,
                                "name": child_name,
                                "offset": child_node.offset,
                                "data_type": child_node.data_type,
                            }
                            for child_name, child_node in merkle_node.children.items()
                        ]
                        self.repository.insert_struct(blob_hash, merkle_node, unwind_param)

        return len(j_pdb.items())

    def insert_symbols(self, blob_hash: str, symbols: Dict) -> int:
        # Parse symbols using pure function
        parsed_symbols = parse_symbols_from_json(symbols)

        # Convert to param format for Neo4j
        param_list = []
        for symbol in parsed_symbols:
            param_list.append({"hash": symbol["hash"], "sym_name": symbol["name"], "address": symbol["address"]})
            self.logger.debug("Symbol %s (%s)", symbol["name"], symbol["address"])

        # Use repository to insert symbols
        self.repository.insert_symbols(blob_hash, param_list)
        return len(symbols.items())

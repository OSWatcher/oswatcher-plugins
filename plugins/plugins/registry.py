from __future__ import annotations

import hashlib
from pathlib import Path, PurePath
from typing import Dict, Generator, Iterator

from attrs import define, field
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleLabel, MerkleNode, Node
from neogit.core.visitor import VisitedNode
from neogit.model.merkle import Blob
from neogit.model.neo import Commit, Tree
from regipy import RegistryHive, Subkey, Value

from plugins.types import AbstractPlugin

"""Directory path to system-wide hives files"""
S32_CONFIG = PurePath("/Windows/System32/config")

"""HKEY_LOCAL_MACHINE root key path"""
HKLM = PurePath("HKEY_LOCAL_MACHINE")
"""HKEY_LOCAL_MACHINE root key path"""
HKU = PurePath("HKEY_USERS")
"""registry key name of the BCD mount point in HKLM"""
BCD_MOUNT_NAME = "BCD00000000"

"""Mapping from filepath to corresponding registry hive
We use PureWindowsPath for case insensitive matching"""
HIVE_MAPPING: Dict[PurePath, PurePath] = {
    # HKLM hives
    S32_CONFIG / "SAM": HKLM / "SAM",
    S32_CONFIG / "SECURITY": HKLM / "SECURITY",
    S32_CONFIG / "SOFTWARE": HKLM / "SOFTWARE",
    S32_CONFIG / "SYSTEM": HKLM / "SYSTEM",
    # BCD
    #    Bios boot
    PurePath("/boot/BCD"): HKLM / BCD_MOUNT_NAME,
    #    EFI boot
    PurePath("/EFI/Microsoft/Boot/BCD"): HKLM / BCD_MOUNT_NAME,
    # HKEY_USERS hives
    S32_CONFIG / "DEFAULT": HKU / ".Default",
}


@define(auto_attribs=True)
class CommonWinRegNode(Node):

    @property
    def name(self) -> str:
        raise NotImplementedError


@define(auto_attribs=True)
class WinRegValueNode(CommonWinRegNode):
    value: Value

    @property
    def name(self) -> str:
        return self.value.name


class WinRegKeyNode(CommonWinRegNode):

    def __init__(self, key: Subkey):
        self.key = key

    @property
    def name(self) -> str:
        return self.key.name

    def iter_child_nodes(self) -> Iterator[Node]:
        for sub_key in self.key.iter_subkeys():
            yield WinRegKeyNode(sub_key)
            for value in sub_key.iter_values():
                yield WinRegValueNode(value)


@define(auto_attribs=True)
class WinRegValueMerkleNode(MerkleNode):
    value: Value = field(kw_only=True)


@define(auto_attribs=True)
class WinRegKeyMerkleNode(MerkleNode):
    key: Subkey = field(kw_only=True)


class WinRegMerkleVisitor(MerkleVisitor):

    def visit_WinRegValueNode(
        self, node: WinRegValueNode, hash_obj: hashlib._Hash, *args, **kwargs
    ) -> Generator[VisitedNode, None, None]:
        hash_obj.update(f"{node.value.name}{node.value.value}{node.value.value_type}".encode())
        merkle_node = WinRegValueMerkleNode(hash=hash_obj.hexdigest(), label=MerkleLabel.Blob, value=node.value)
        yield VisitedNode(node, merkle_node)

    def visit_WinRegKeyNode(
        self, node: WinRegKeyNode, hash_obj: hashlib._Hash, *args, **kwargs
    ) -> Generator[VisitedNode, None, None]:
        merkle_children = {}
        # sort by 2 criterias
        # - keys first
        # - values second
        # then name
        for child_node in sorted(node.iter_child_nodes(), key=lambda e: (not isinstance(e, WinRegKeyNode), e.name)):
            last_visited = None
            for visited_node in self.visit(child_node):
                yield visited_node
                last_visited = visited_node
            merkle_node = last_visited.return_value
            data = f"{child_node.name}{merkle_node.hash}\n".encode()
            hash_obj.update(data)
            # clear out the current merkle node children Dict
            # so we don't end up with a giant tree in memory
            merkle_node.children.clear()
            merkle_children[child_node.name] = merkle_node
        # compute final hash
        merkle_node = WinRegKeyMerkleNode(
            hash=hash_obj.hexdigest(), children=merkle_children, label=MerkleLabel.Tree, key=node.key
        )
        yield VisitedNode(node, merkle_node)


@define(auto_attribs=True)
class WinRegistryPlugin(AbstractPlugin):

    def run(self, commit: Commit):
        fs: Tree = commit.filesystem.single()
        for hive_path, root_hive in HIVE_MAPPING.items():
            try:
                blob = fs.get_blob_at_path(hive_path)
                with self.downloaded_file(blob.hash) as hive_local_path:
                    self.logger.info("Dumping %s", hive_path)
                    node = self.dump_hive(hive_path, hive_local_path)
                    if node is not None:
                        # attach Key to blob
                        self.attach_root_key_to_blob(blob, node, root_hive.name)
            except FileNotFoundError:
                self.logger.warning("Not found: %s", hive_path)

    def dump_hive(self, hive_win_path: PurePath, hive_local_path: Path):
        """Dump a Windows registry hive

        :param hive_local_path: host path to the download hive file
        """
        # load hive
        try:
            hive = RegistryHive(hive_local_path)
        except Exception as e:
            self.logger.warning("Failed to load hive %s", hive_win_path)
            self.logger.debug(e)
            return
        root_node = WinRegKeyNode(key=hive.root)
        visitor = WinRegMerkleVisitor()
        last_node = None
        for node in visitor.visit(root_node):
            if isinstance(node.node, WinRegKeyNode):
                self.insert_from_visited_node_cypher(node)
                last_node = node
        return last_node

    def insert_from_visited_node_cypher(self, node: VisitedNode):
        self.create_parent(node)
        self.insert_child_values(node)
        self.insert_child_keys(node)

    def create_parent(self, node: VisitedNode):
        query = """
        MERGE (n:WinRegKey {hash: $hash})
        """
        self.neogit.db.cypher_query(query, {"hash": node.return_value.hash})

    def insert_child_values(self, node: VisitedNode):
        """Create child Values"""
        query = """
        MATCH (p:WinRegKey {hash: $parent_hash})
        WITH p
        UNWIND $unwind_param as x
        MERGE (n:WinRegValue {hash: x.hash, value: x.value, type: x.type})
        MERGE (p)-[:HAS_WINREG_VALUE {name: x.name}]->(n)
        """
        unwind_param = [
            {
                "name": child_name,
                "hash": child_node.hash,
                "value": child_node.value.value,
                "type": child_node.value.value_type,
            }
            for child_name, child_node in node.return_value.children.items()
            if child_node.label == MerkleLabel.Blob
        ]
        self.neogit.db.cypher_query(query, {"parent_hash": node.return_value.hash, "unwind_param": unwind_param})

    def insert_child_keys(self, node: VisitedNode):
        """Create child Keys"""
        query = """
        MATCH (p:WinRegKey {hash: $parent_hash})
        WITH p
        UNWIND $unwind_param as x
        MERGE (n:WinRegKey {hash: x.hash})
        MERGE (p)-[:HAS_WINREG_VALUE {name: x.name}]->(n)
        """
        unwind_param = [
            {
                "name": child_name,
                "hash": child_node.hash,
            }
            for child_name, child_node in node.return_value.children.items()
            if child_node.label == MerkleLabel.Tree
        ]
        self.neogit.db.cypher_query(query, {"parent_hash": node.return_value.hash, "unwind_param": unwind_param})

    def attach_root_key_to_blob(self, blob: Blob, root_node: VisitedNode, root_name: str):
        query = """
        MATCH (b:Blob {hash: $blob_hash})
        WITH b
        MATCH (k:WinRegKey {hash: $root_hash})
        WITH b, k
        MERGE (b)-[:HAS_WINREG_KEY {name: $name}]->(k)
        """
        self.neogit.db.cypher_query(
            query, {"blob_hash": blob.hash, "root_hash": root_node.return_value.hash, "name": root_name}
        )

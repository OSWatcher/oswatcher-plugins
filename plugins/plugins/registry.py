from __future__ import annotations

import hashlib
from pathlib import Path, PurePath
from typing import Dict, Iterator, List

from attrs import define, field
from neogit.core.merkle import MerkleVisitor
from neogit.core.model import MerkleLabel, MerkleNode, Node
from neogit.core.visitor import VisitedNode
from neogit.model.merkle import Blob
from neogit.model.neo import Commit, Tree
from regipy import NKRecord, RegistryHive, Subkey, Value

from plugins.types import AbstractPlugin, UniqueConstraint

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
    path: PurePath = field()

    @property
    def name(self) -> str:
        raise NotImplementedError

    @property
    def fullpath(self) -> PurePath:
        return self.path / self.name


@define(auto_attribs=True)
class WinRegValueNode(CommonWinRegNode):
    value: Value = field()

    @property
    def name(self) -> str:
        return self.value.name


@define(auto_attribs=True)
class WinRegKeyNode(CommonWinRegNode):
    key: NKRecord = field()

    @property
    def name(self) -> str:
        return self.key.name

    def iter_child_nodes(self) -> Iterator[Node]:
        for sub_key in self.key.iter_subkeys():
            yield WinRegKeyNode(self.fullpath, sub_key)
        for value in self.key.iter_values():
            yield WinRegValueNode(self.fullpath, value)


@define(auto_attribs=True)
class WinRegValueMerkleNode(MerkleNode):
    value: Value = field(kw_only=True)


@define(auto_attribs=True)
class WinRegKeyMerkleNode(MerkleNode):
    key: Subkey = field(kw_only=True)


class WinRegMerkleVisitor(MerkleVisitor):

    def visit_WinRegValueNode(self, node: WinRegValueNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        hash_obj.update(f"{node.value.name}{node.value.value}{node.value.value_type}".encode())
        merkle_node = WinRegValueMerkleNode(hash=hash_obj.hexdigest(), label=MerkleLabel.Blob, value=node.value)
        return VisitedNode(node, merkle_node)

    def visit_WinRegKeyNode(self, node: WinRegKeyNode, hash_obj: hashlib._Hash, *args, **kwargs) -> VisitedNode:
        self.logger.debug("Visiting Key %s", node.fullpath)
        merkle_children = {}
        # sort by 2 criterias
        # - keys first
        # - values second
        # then name
        for child_node in sorted(node.iter_child_nodes(), key=lambda e: (not isinstance(e, WinRegKeyNode), e.name)):
            visited_node = self.visit(child_node)
            merkle_node = visited_node.return_value
            data = f"{child_node.name}{merkle_node.hash}\n".encode()
            hash_obj.update(data)
            # clear out the current merkle node children Dict
            # so we don't end up with a giant tree in memory
            # TODO: this breaks the plugin: when the node is about to be inserted, he apparently has no children anymore
            # merkle_node.children.clear()
            merkle_children[child_node.name] = merkle_node
        # compute final hash
        merkle_node = WinRegKeyMerkleNode(
            hash=hash_obj.hexdigest(), children=merkle_children, label=MerkleLabel.Tree, key=node.key
        )
        return VisitedNode(node, merkle_node)


@define(auto_attribs=True)
class WinRegistryPlugin(AbstractPlugin):

    def constraints_data(self) -> List[UniqueConstraint]:
        return [
            UniqueConstraint(label="WinRegKey", property_list=["hash"]),
            UniqueConstraint(label="WinRegValue", property_list=["hash"]),
        ]

    def run(self, commit: Commit):
        fs: Tree = commit.filesystem.single()
        for hive_path, root_hive in HIVE_MAPPING.items():
            try:
                blob = fs.get_blob_at_path(hive_path)
                with self.downloaded_file(blob.hash) as hive_local_path:
                    self.logger.info("Dumping %s", hive_path)
                    node = self.dump_hive(hive_path, hive_local_path, root_hive)
                    if node is not None:
                        # attach Key to blob
                        self.attach_root_key_to_blob(blob, node.return_value, root_hive.name)
            except FileNotFoundError:
                self.logger.warning("Not found: %s", hive_path)

    def dump_hive(self, hive_win_path: PurePath, hive_local_path: Path, root_hive: PurePath):
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
        root_node = WinRegKeyNode(root_hive, key=hive.root)
        with WinRegMerkleVisitor(thread=True) as visitor:
            visitor.run_visit(root_node)
            last_node = None
            for node in visitor.as_gen():
                if isinstance(node.return_value, WinRegKeyMerkleNode):
                    self.insert_from_visited_node_cypher(node.return_value)
                    last_node = node
                    # clear children to save RAM
                    node.return_value.children.clear()
            return last_node

    def insert_from_visited_node_cypher(self, node: WinRegKeyMerkleNode):
        self.create_parent(node)
        self.insert_child_values(node)
        self.insert_child_keys(node)

    def create_parent(self, node: WinRegKeyMerkleNode):
        query = """
        MERGE (n:WinRegKey {hash: $hash})
        """
        self.neogit.db.cypher_query(query, {"hash": node.hash})

    def insert_child_values(self, node: WinRegKeyMerkleNode):
        """Create child Values"""
        query = """
        MATCH (p:WinRegKey {hash: $parent_hash})
        WITH p
        UNWIND $unwind_param as x
        MERGE (n:WinRegValue {hash: x.hash, value: x.value, type: x.type})
        MERGE (p)-[:HAS_CHILD {name: x.name}]->(n)
        """
        # note: Neo4j can store integer as signed 64 bits number
        # however the Windows registry can contain REG_QWORD values up to 2^64 - 1
        # so we need to ensure the value is casted as a string here
        unwind_param = [
            {
                "name": child_name,
                "hash": child_node.hash,
                "value": str(child_node.value.value),
                "type": child_node.value.value_type,
            }
            for child_name, child_node in node.children.items()
            if child_node.label == MerkleLabel.Blob
        ]
        self.neogit.db.cypher_query(query, {"parent_hash": node.hash, "unwind_param": unwind_param})

    def insert_child_keys(self, node: WinRegKeyMerkleNode):
        """Create child Keys"""
        query = """
        MATCH (p:WinRegKey {hash: $parent_hash})
        WITH p
        UNWIND $unwind_param as x
        MERGE (n:WinRegKey {hash: x.hash})
        MERGE (p)-[:HAS_CHILD {name: x.name}]->(n)
        """
        unwind_param = [
            {
                "name": child_name,
                "hash": child_node.hash,
            }
            for child_name, child_node in node.children.items()
            if child_node.label == MerkleLabel.Tree
        ]
        self.neogit.db.cypher_query(query, {"parent_hash": node.hash, "unwind_param": unwind_param})

    def attach_root_key_to_blob(self, blob: Blob, root_node: WinRegKeyMerkleNode, root_name: str):
        query = """
        MATCH (b:Blob {hash: $blob_hash})
        WITH b
        MATCH (k:WinRegKey {hash: $root_hash})
        WITH b, k
        MERGE (b)-[:HAS_WINREG {name: $name}]->(k)
        """
        self.neogit.db.cypher_query(query, {"blob_hash": blob.hash, "root_hash": root_node.hash, "name": root_name})

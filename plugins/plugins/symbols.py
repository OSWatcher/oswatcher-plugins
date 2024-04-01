from binascii import hexlify
from pathlib import Path
from typing import Dict
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import lief
from attrs import define
from neogit.model.neo import Commit
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver

from plugins.types import AbstractPlugin


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
                except ValueError:
                    continue
                self.logger.info(location)
                ctx = Context()
                try:
                    j_data = PdbReader(ctx, location).get_json()
                except ValueError:
                    self.logger.exception("Failed to parse PDB")
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

    def insert_symbols(self, blob_hash, symbols: Dict):
        param_list = []
        for sym, value in symbols.items():
            if sym.startswith("?") or sym.startswith("$"):
                continue
            address = value["address"]
            param_list.append(
                {
                    "sym_name": sym,
                    "address": address,
                }
            )
            self.logger.info("Insert %s (%s)", sym, hex(address))
        query = """
        MATCH (b:Blob {hash: $blob_hash})
        WITH b
        UNWIND $unwind as p
        MERGE (b)-[:HAS_SYMBOL {address: p.address}]->(s:Symbol {name: p.sym_name})
        """
        self.neogit.db.cypher_query(query, {"blob_hash": blob_hash, "unwind": param_list})

    def parse_pdb_json(self, blob_hash, j_pdb: Dict):
        self.insert_symbols(blob_hash, j_pdb["symbols"])

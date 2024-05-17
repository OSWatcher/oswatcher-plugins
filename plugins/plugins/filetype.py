import tempfile
from io import BytesIO
from typing import List

import magic
from attrs import define
from neogit.model.neo import Commit

from plugins.types import AbstractPlugin, UniqueConstraint


@define(auto_attribs=True)
class FileTypePlugin(AbstractPlugin):

    def constraints_data(self) -> List[UniqueConstraint]:
        return [
            UniqueConstraint(label="MimeType", property_list=["mime"]),
        ]

    def run(self, commit: Commit):
        fs = commit.filesystem.single()
        self.logger.info("root: %s", fs)
        for index, (path, blob) in enumerate(fs.all_blobs()):
            self.logger.debug("[%s] path: %s, blob: %s", index, path, blob.hash)
            # download blob
            bio = BytesIO()
            total_size = 0
            tmp_file = None
            for chunk in self.neogit.download_object_as_stream(blob.hash):
                total_size += len(chunk)
                if total_size <= 50 * 1024 * 1024:
                    bio.write(chunk)
                else:
                    # continue write into a temporary file instead
                    if not tmp_file:
                        tmp_file = tempfile.NamedTemporaryFile(delete=True)
                        # transfer content
                        tmp_file.write(bio.read())
                        bio.close()
                    tmp_file.write(chunk)

            # identify file
            if tmp_file:
                file_type = magic.from_file(tmp_file.name, mime=True)
                tmp_file.close()
            else:
                file_type = magic.from_buffer(bio.getvalue(), mime=True)
                bio.close()
            self.logger.info("[%s] blob: %s - %s", index, blob.hash, file_type)
            # Dynamically create the relationship using a Cypher query
            query = """
            MERGE (m:MimeType {mime: $mime_type})
            WITH m
            MATCH (b:Blob {hash: $blob_hash})
            MERGE (b)-[:HAS_MIME_TYPE]->(m)
            """
            self.neogit.db.cypher_query(query, {"blob_hash": blob.hash, "mime_type": file_type})

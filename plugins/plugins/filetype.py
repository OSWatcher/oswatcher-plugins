from attrs import define
from neogit.model.neo import Commit

from plugins.types import AbstractPlugin


@define(auto_attribs=True)
class FileTypePlugin(AbstractPlugin):

    def run(self, commit: Commit):
        fs = commit.filesystem.single()
        self.logger.info("root: %s", fs)
        for index, blob in enumerate(fs.all_blobs()):
            self.logger.info("[%s] blob: %s", index, blob)

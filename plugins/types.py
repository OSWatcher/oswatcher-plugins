# define abstract Plugin Class

import logging
import tempfile
from abc import abstractmethod
from contextlib import contextmanager
from typing import Any

from attrs import Factory, define, field
from neogit.model.neo import Commit
from neogit.service import Neogit


@define(auto_attribs=True)
class AbstractPlugin:
    logger: logging.Logger = field(
        init=False,
        default=Factory(
            lambda self: logging.getLogger(f"{self.__module__}.{self.__class__.__name__}"),
            takes_self=True,
        ),
    )
    neogit: Neogit = field(init=False, default=Neogit())

    def __call__(self, commit: Commit, *args: Any, **kwds: Any) -> Any:
        """Execute the run method inside a neomodel transaction"""
        with self.neogit.db.transaction:
            self.run(commit)

    @abstractmethod
    def run(self, commit: Commit):
        """Run the plugin"""
        pass

    @contextmanager
    def downloaded_file(self, hash: str):
        with tempfile.NamedTemporaryFile(delete=True) as tmp_file:
            for chunk in self.neogit.download_object_as_stream(hash):
                tmp_file.write(chunk)
            tmp_file.flush()
            yield tmp_file.name

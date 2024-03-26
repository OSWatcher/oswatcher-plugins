# define abstract Plugin Class

import logging
from abc import abstractmethod

from attrs import Factory, define, field
from neogit.service import Neogit


@define(auto_attribs=True)
class AbstractPlugin:
    logger: logging.Logger = field(
        init=False,
        default=Factory(
            lambda self: logging.getLogger(
                f"{self.__module__}.{self.__class__.__name__}"
            ),
            takes_self=True,
        ),
    )
    neogit: Neogit = field(init=False, default=Neogit())

    def _trans_run(self):
        """Execute the run method inside a neomodel transaction"""
        with self.neogit.db.transaction:
            self.run()

    @abstractmethod
    def run(self):
        """Run the plugin"""
        pass

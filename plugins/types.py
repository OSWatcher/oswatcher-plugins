# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

# define abstract Plugin Class

import logging
import tempfile
from abc import abstractmethod
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from typing import Any, List

from attrs import Factory, define, field
from neogit.model.neo import Commit, PluginRun
from neogit.service import Neogit
from neogit.utils import BetterContextManager

QUERY_CREATE_UNIQUE_CONSTRAINT = """
CREATE CONSTRAINT {name}
IF NOT EXISTS
FOR (n:{label})
REQUIRE n.{property} IS UNIQUE
""".strip()


@define(auto_attribs=True)
class UniqueConstraint:
    label: str = field()
    property_list: list[str] = field()


@define(auto_attribs=True)
class AbstractPlugin(BetterContextManager):
    logger: logging.Logger = field(
        init=False,
        default=Factory(
            lambda self: logging.getLogger(f"{self.__module__}.{self.__class__.__name__}"),
            takes_self=True,
        ),
    )
    neogit: Neogit = field(init=False, default=Neogit())

    def __call__(self, commit: Commit, plugin_name: str, *args: Any, force: bool = False, **kwds: Any) -> Any:
        """Execute the run method inside a neomodel transaction

        Args:
            commit: The commit to process
            plugin_name: Name of the plugin being run
            force: If True, rerun the plugin even if already executed
        """
        with suppress(IndexError):
            plugin_run_node = commit.plugin.all()[0]
            plugin_date = getattr(plugin_run_node, plugin_name, None)
            if plugin_date is not None and not force:
                self.logger.info(
                    "Plugin run node already executed at %s for commit %s", plugin_run_node.filetype, commit.hash
                )
                return
            if plugin_date is not None and force:
                self.logger.info(
                    "Force rerun enabled - re-executing plugin for commit %s (previously run at %s)",
                    commit.hash,
                    plugin_date,
                )
        # can't mix schema modification and write query in the same transaction
        with self.neogit.db.transaction:
            self.ensure_constraints()
        # TODO: fix transaction
        # with self.neogit.db.transaction:
        self.run(commit)
        with self.neogit.db.write_transaction:
            try:
                plugin_run_node = commit.plugin.all()[0]
                self.logger.info("Plugin run node already exists for commit %s", commit.hash)
            except IndexError:
                self.logger.info("Creating plugin run node for commit %s", commit.hash)
                plugin_run_node = PluginRun()
                # node needs to be saved for the connection to be created as well
                plugin_run_node.save()
            # ensure connected
            commit.plugin.connect(plugin_run_node)
            # update plugin run with datetime (timzeone-aware UTC)
            setattr(plugin_run_node, plugin_name, datetime.now(timezone.utc))
            plugin_run_node.save()

        self.logger.info("Plugin run node updated for commit %s", commit.hash)

    def ensure_constraints(self):
        """Ensure the constraints are in the database"""
        for constraint in self.constraints_data():
            for prop in constraint.property_list:
                name = f"{constraint.label.lower()}_{prop}_unique"
                query = QUERY_CREATE_UNIQUE_CONSTRAINT.format(name=name, label=constraint.label, property=prop)
                self.neogit.db.cypher_query(query)

    def constraints_data(self) -> List[UniqueConstraint]:
        """Return the constraints data"""
        return []

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

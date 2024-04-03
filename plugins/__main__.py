import logging

import click
from neogit.model.neo import Commit

from plugins.plugins import MAP_PLUGIN, PluginType


def setup_logging(debug_enabled: bool):
    level = logging.DEBUG if debug_enabled else logging.INFO
    logging.basicConfig(level=level)
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("volatility3.framework.symbols.windows.pdbconv").setLevel(logging.WARNING)
    logging.getLogger("volatility3.framework.layers.resources").setLevel(logging.WARNING)


@click.command()
@click.option("--debug", "-d", is_flag=True, help="Toggle debug output")
@click.argument("commit_hash")
@click.argument("plugin_type_str")
def runner(debug, commit_hash: str, plugin_type_str: str):
    """Plugin Runner"""
    setup_logging(debug)
    # get plugin type enum
    try:
        plugin_type = PluginType[plugin_type_str.upper()]
    except KeyError:
        logging.error(
            "Unknow plugin type: %s. Available plugins: %s",
            plugin_type_str,
            [e.name for e in PluginType],
        )
        return 1
    # get Plugin
    try:
        plugin_cls = MAP_PLUGIN[plugin_type]
    except KeyError:
        logging.error("Unregistered plugin: %s", plugin_type.name)
        return 1

    # get commit object
    commit = Commit.nodes.get(hash=commit_hash)

    # instantiate plugin
    with plugin_cls() as plugin:
        # __call__
        plugin(commit)

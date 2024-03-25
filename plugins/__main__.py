import logging

import click


def setup_logging(debug_enabled: bool):
    level = logging.DEBUG if debug_enabled else logging.INFO
    logging.basicConfig(level=level)


@click.command()
@click.option("--debug", "-d", is_flag=True, help="Toggle debug output")
@click.argument("commit_hash")
def runner(debug, commit_hash: str):
    """Plugin Runner"""
    setup_logging(debug)
    logging.info("Hello !")

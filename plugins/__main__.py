"""Plugin Runner

Usage:
  runner [options] <commit_hash>

Options:
  -h --help             Show this screen.
  --version             Show version.
  -d --debug            Toogle debug output
"""

from functools import wraps
import logging


from docopt import docopt



def setup_logging(debug_enabled: bool):
    level = logging.INFO
    if debug_enabled:
        level = logging.DEBUG
    logging.basicConfig(level=level)


def handle_cmdline():
    args = docopt(__doc__)
    setup_logging(args["--debug"])
    logging.info("Hello !")

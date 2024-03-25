# define abstract Plugin Class

from contextlib import AbstractContextManager
from types import TracebackType
from typing import Self
from .config import settings
from neomodel import db as neomodel_db

class AbstractPlugin(AbstractContextManager):

    def __init__(self) -> None:
        super().__init__()
        neomodel_db.set_connection(settings.neo4j.url_full)


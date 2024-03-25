# define abstract Plugin Class

from contextlib import AbstractContextManager

from neomodel import db as neomodel_db

from .config import settings


class AbstractPlugin(AbstractContextManager):

    def __init__(self) -> None:
        super().__init__()
        neomodel_db.set_connection(settings.neo4j.url_full)

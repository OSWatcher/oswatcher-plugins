from enum import Enum, auto

from .filetype import FileTypePlugin


class PluginType(Enum):
    FILETYPE = auto()


MAP_PLUGIN = {PluginType.FILETYPE: FileTypePlugin}

__all__ = ["MAP_PLUGIN", "PluginType"]

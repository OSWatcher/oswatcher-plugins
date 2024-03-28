from enum import Enum, auto

from .filetype import FileTypePlugin
from .symbols import SymbolsPlugin


class PluginType(Enum):
    FILETYPE = auto()
    SYMBOLS = auto()


MAP_PLUGIN = {PluginType.FILETYPE: FileTypePlugin, PluginType.SYMBOLS: SymbolsPlugin}

__all__ = ["MAP_PLUGIN", "PluginType", "SymbolsPlugin"]

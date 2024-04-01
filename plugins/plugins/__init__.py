from enum import Enum, auto

from .filetype import FileTypePlugin
from .registry import WinRegistryPlugin
from .symbols import SymbolsPlugin


class PluginType(Enum):
    FILETYPE = auto()
    SYMBOLS = auto()
    WINREG = auto()


MAP_PLUGIN = {
    PluginType.FILETYPE: FileTypePlugin,
    PluginType.SYMBOLS: SymbolsPlugin,
    PluginType.WINREG: WinRegistryPlugin,
}

__all__ = ["MAP_PLUGIN", "PluginType", "SymbolsPlugin", "WinRegistryPlugin"]

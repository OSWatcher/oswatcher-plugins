from enum import Enum, auto
from typing import Dict, Type

from plugins.types import AbstractPlugin

from .filetype import FileTypePlugin
from .registry import WinRegistryPlugin
from .symbols import SymbolsPlugin


class PluginType(Enum):
    FILETYPE = auto()
    SYMBOLS = auto()
    WINREG = auto()


MAP_PLUGIN: Dict[PluginType, Type[AbstractPlugin]] = {
    PluginType.FILETYPE: FileTypePlugin,
    PluginType.SYMBOLS: SymbolsPlugin,
    PluginType.WINREG: WinRegistryPlugin,
}

__all__ = ["MAP_PLUGIN", "PluginType", "SymbolsPlugin", "WinRegistryPlugin"]

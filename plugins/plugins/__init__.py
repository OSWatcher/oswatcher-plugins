from enum import Enum, auto
from typing import Dict, Type

from plugins.types import AbstractPlugin

from .filetype import FileTypePlugin
from .linux_symbols import LinuxSymbolsPlugin
from .registry import WinRegistryPlugin
from .symbols import SymbolsPlugin
from .syscalls import SyscallsPlugin


class PluginType(Enum):
    FILETYPE = auto()
    SYMBOLS = auto()
    WINREG = auto()
    SYSCALLS = auto()
    LINUX_SYMBOLS = auto()


MAP_PLUGIN: Dict[PluginType, Type[AbstractPlugin]] = {
    PluginType.FILETYPE: FileTypePlugin,
    PluginType.SYMBOLS: SymbolsPlugin,
    PluginType.WINREG: WinRegistryPlugin,
    PluginType.SYSCALLS: SyscallsPlugin,
    PluginType.LINUX_SYMBOLS: LinuxSymbolsPlugin,
}

__all__ = ["MAP_PLUGIN", "PluginType", "SymbolsPlugin", "WinRegistryPlugin", "SyscallsPlugin", "LinuxSymbolsPlugin"]

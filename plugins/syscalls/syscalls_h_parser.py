"""Syscalls.h signature parsing from kernel headers."""

import re
from typing import Optional, List
from dataclasses import dataclass


@dataclass(frozen=True)
class SyscallSignature:
    """Represents a syscall signature with parameters."""
    name: str
    parameters: List[str]


def parse_syscall_signature(syscalls_h_content: str, entry_name: str) -> Optional[SyscallSignature]:
    """Parse syscall signature for a specific entry from syscalls.h content.
    
    Args:
        syscalls_h_content: Content of syscalls.h file
        entry_name: Entry point name like 'sys_read'
        
    Returns:
        SyscallSignature instance or None if not found
    """
    # Use Filippo's regex pattern: (?:asmlinkage|unsigned) long {entry}\(([^)]+)\);
    pattern = rf'(?:asmlinkage|unsigned) long {re.escape(entry_name)}\(([^)]+)\);'
    
    # Make multiline and handle whitespace
    match = re.search(pattern, syscalls_h_content, re.MULTILINE | re.DOTALL)
    
    if not match:
        return None
    
    params_str = match.group(1)
    
    # Handle void case
    if params_str.strip() == "void":
        parameters = []
    else:
        # Split by comma and clean up
        parameters = []
        for param in params_str.split(','):
            param = param.strip()
            # Remove __user qualifier
            param = param.replace('__user ', '')
            parameters.append(param)
    
    # Extract syscall name from entry_name (remove sys_ prefix)
    name = entry_name.replace('sys_', '')
    
    return SyscallSignature(name=name, parameters=parameters)

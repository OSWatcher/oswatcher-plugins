"""Test syscalls.h signature parsing from kernel headers."""

import pytest
from plugins.syscalls.syscalls_h_parser import SyscallSignature


@pytest.mark.parametrize("syscalls_h_content,entry_name,expected", [
    (
        "asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);",
        "sys_read",
        SyscallSignature(name="read", parameters=["unsigned int fd", "char *buf", "size_t count"])
    ),
    (
        "asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);",
        "sys_write", 
        SyscallSignature(name="write", parameters=["unsigned int fd", "const char *buf", "size_t count"])
    ),
    (
        "unsigned long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);",
        "sys_mmap",
        SyscallSignature(name="mmap", parameters=[
            "unsigned long addr", "unsigned long len", "unsigned long prot", 
            "unsigned long flags", "unsigned long fd", "unsigned long off"
        ])
    ),
    (
        "asmlinkage long sys_getpid(void);",
        "sys_getpid",
        SyscallSignature(name="getpid", parameters=[])
    ),
    (
        "asmlinkage long sys_close(unsigned int fd);",
        "sys_close",
        SyscallSignature(name="close", parameters=["unsigned int fd"])
    ),
])
def test_parse_syscall_signature(syscalls_h_content, entry_name, expected):
    """Test parsing syscall signatures from syscalls.h content."""
    from plugins.syscalls.syscalls_h_parser import parse_syscall_signature
    
    result = parse_syscall_signature(syscalls_h_content, entry_name)
    assert result == expected


def test_parse_syscall_signature_not_found():
    """Test handling when syscall signature is not found."""
    from plugins.syscalls.syscalls_h_parser import parse_syscall_signature
    
    content = "asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);"
    result = parse_syscall_signature(content, "sys_nonexistent")
    assert result is None


def test_parse_syscall_signature_multiline():
    """Test parsing syscall signature across multiple lines."""
    from plugins.syscalls.syscalls_h_parser import parse_syscall_signature
    
    content = """
    asmlinkage long sys_openat(int dfd, const char __user *filename,
                               int flags, umode_t mode);
    """
    expected = SyscallSignature(name="openat", parameters=[
        "int dfd", "const char *filename", "int flags", "umode_t mode"
    ])
    
    result = parse_syscall_signature(content, "sys_openat")
    assert result == expected
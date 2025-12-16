"""Test syscall table parsing from syscall_64.tbl format."""

import pytest

from plugins.syscalls.kernel_parser import SyscallIndex


@pytest.mark.parametrize(
    "line,expected",
    [
        ("0\tcommon\tread\tsys_read", SyscallIndex(name="read", index=0)),
        ("1\tcommon\twrite\tsys_write", SyscallIndex(name="write", index=1)),
        ("13\t64\trt_sigaction\tsys_rt_sigaction", SyscallIndex(name="rt_sigaction", index=13)),
        ("16\t64\tioctl\tsys_ioctl", SyscallIndex(name="ioctl", index=16)),
        ("17\tcommon\tpread64\tsys_pread64", SyscallIndex(name="pread64", index=17)),
    ],
)
def test_parse_syscall_table_line(line, expected):
    """Test parsing individual syscall table lines."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    result = parse_syscall_table_line(line)
    assert result == expected


def test_parse_syscall_table_line_spaces():
    """Test parsing with spaces instead of tabs."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    result = parse_syscall_table_line("0       common  read                    sys_read")
    assert result == SyscallIndex(name="read", index=0)


def test_parse_syscall_table_line_x32_filtered():
    """Test that x32 ABI syscalls are filtered out for 64-bit focus."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    # Should return None for x32 syscalls since we focus on 64-bit
    result = parse_syscall_table_line("512\tx32\tmq_notify\tcompat_sys_mq_notify")
    assert result is None


def test_parse_syscall_table_line_comment():
    """Test error handling for comment lines."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    result = parse_syscall_table_line("# This is a comment")
    assert result is None


def test_parse_syscall_table_line_empty():
    """Test error handling for empty lines."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    result = parse_syscall_table_line("")
    assert result is None


def test_parse_syscall_table_line_missing_entry_point():
    """Test parsing syscall lines without entry points."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    result = parse_syscall_table_line("134\t64\tuselib")
    assert result == SyscallIndex(name="uselib", index=134)


def test_parse_syscall_table_line_invalid():
    """Test error handling for invalid format."""
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line

    with pytest.raises(ValueError):
        parse_syscall_table_line("invalid format")

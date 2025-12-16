"""Integration tests for syscall plugin merkle node transformation.

Tests the full flow from syscall data extraction through merkle node creation.
"""

from unittest.mock import Mock

import pytest

from plugins.plugins.syscalls import SyscallsPlugin
from plugins.syscalls.filesystem import KernelInfo


class TestSyscallMerkleTransformation:
    """Test end-to-end merkle node transformation."""

    @pytest.fixture
    def mock_plugin(self):
        """Create a mock SyscallsPlugin."""
        plugin = SyscallsPlugin()
        plugin.logger = Mock()
        return plugin

    def test_transform_and_visit_single_kernel(self, mock_plugin):
        """_transform_and_visit should create merkle nodes for single kernel."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            )
        ]

        syscall_data = {
            "v5.15": [
                {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": ["unsigned int fd"]},
                {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
            ]
        }

        # Should not raise any exceptions
        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Verify logger was called with expected messages
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        assert any("Creating SyscallTableNode for v5.15" in msg for msg in log_calls)
        assert any("Created SyscallTableMerkleNode" in msg for msg in log_calls)

    def test_transform_and_visit_multiple_kernels(self, mock_plugin):
        """_transform_and_visit should handle multiple kernel versions."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            ),
            KernelInfo(
                version="v6.1",
                blob_hash="def456",
                filename="vmlinuz-6.1.0-13-amd64",
                architecture="lief._lief.ELF.ARCH.x86_64",
            ),
        ]

        syscall_data = {
            "v5.15": [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}],
            "v6.1": [{"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None}],
        }

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should log creation for both kernels
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        assert any("v5.15" in msg for msg in log_calls)
        assert any("v6.1" in msg for msg in log_calls)

    def test_transform_and_visit_missing_version_data(self, mock_plugin):
        """_transform_and_visit should skip kernels without syscall data."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            ),
            KernelInfo(
                version="v6.1",
                blob_hash="def456",
                filename="vmlinuz-6.1.0-13-amd64",
                architecture="lief._lief.ELF.ARCH.x86_64",
            ),
        ]

        # Only v5.15 has data
        syscall_data = {
            "v5.15": [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}],
        }

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should only log v5.15
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        creation_logs = [msg for msg in log_calls if "Creating SyscallTableNode" in msg]
        assert len(creation_logs) == 1
        assert "v5.15" in creation_logs[0]

    def test_transform_and_visit_empty_syscall_data(self, mock_plugin):
        """_transform_and_visit should handle empty syscall data gracefully."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            )
        ]

        syscall_data = {}

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should log "No syscall data to transform"
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        assert any("No syscall data to transform" in msg for msg in log_calls)

    def test_transform_and_visit_syscall_count(self, mock_plugin):
        """_transform_and_visit should log correct syscall count."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            )
        ]

        syscall_data = {
            "v5.15": [
                {"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None},
                {"name": "write", "index": 1, "entry_point": "sys_write", "parameters": None},
                {"name": "open", "index": 2, "entry_point": "sys_open", "parameters": None},
            ]
        }

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should log "with 3 syscalls"
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        creation_logs = [msg for msg in log_calls if "Creating SyscallTableNode" in msg]
        assert len(creation_logs) == 1
        assert "with 3 syscalls" in creation_logs[0]

    def test_transform_and_visit_merkle_hash_logged(self, mock_plugin):
        """_transform_and_visit should log merkle node hash."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            )
        ]

        syscall_data = {
            "v5.15": [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}],
        }

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should log hash (first 8 chars)
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        merkle_logs = [msg for msg in log_calls if "Created SyscallTableMerkleNode: hash=" in msg]
        assert len(merkle_logs) == 1
        assert "arch=" in merkle_logs[0]
        assert "children=" in merkle_logs[0]

    def test_transform_and_visit_different_architectures(self, mock_plugin):
        """_transform_and_visit should handle different architectures."""
        kernel_info_list = [
            KernelInfo(
                version="v5.15",
                blob_hash="abc123",
                filename="vmlinuz-5.15.0-91-generic",
                architecture="lief._lief.ELF.ARCH.x86_64",
            ),
            KernelInfo(
                version="v5.15",
                blob_hash="def456",
                filename="vmlinuz-5.15.0-91-i386",
                architecture="lief._lief.ELF.ARCH.i386",
            ),
        ]

        # Same version, different architectures
        syscall_data = {
            "v5.15": [{"name": "read", "index": 0, "entry_point": "sys_read", "parameters": None}],
        }

        mock_plugin._transform_and_visit(kernel_info_list, syscall_data)

        # Should create nodes for both architectures
        log_calls = [call.args[0] for call in mock_plugin.logger.info.call_args_list]
        creation_logs = [msg for msg in log_calls if "Creating SyscallTableNode" in msg]
        assert len(creation_logs) == 2
        assert any("x86_64" in msg for msg in creation_logs)
        assert any("i386" in msg for msg in creation_logs)

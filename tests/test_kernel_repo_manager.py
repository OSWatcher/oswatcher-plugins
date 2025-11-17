"""Test kernel repository management using git show for blob extraction."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def temp_cache_dir():
    """Create temporary cache directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


def test_ensure_kernel_repo_clones_if_missing(temp_cache_dir):
    """Test that kernel repo is cloned if it doesn't exist."""
    from plugins.syscalls.kernel_repo_manager import ensure_kernel_repo

    with patch("git.Repo.clone_from") as mock_clone:
        mock_repo = Mock()
        mock_clone.return_value = mock_repo

        repo = ensure_kernel_repo(str(temp_cache_dir))

        # Should clone the repo
        mock_clone.assert_called_once_with("https://github.com/torvalds/linux.git", temp_cache_dir / "linux")
        assert repo == mock_repo


def test_ensure_kernel_repo_uses_existing(temp_cache_dir):
    """Test that existing kernel repo is reused."""
    from plugins.syscalls.kernel_repo_manager import ensure_kernel_repo

    # Create existing repo directory
    linux_dir = temp_cache_dir / "linux"
    linux_dir.mkdir()
    (linux_dir / ".git").mkdir()

    with patch("git.Repo") as mock_repo_class:
        mock_repo = Mock()
        mock_repo_class.return_value = mock_repo

        repo = ensure_kernel_repo(str(temp_cache_dir))

        # Should open existing repo
        mock_repo_class.assert_called_once_with(linux_dir)
        assert repo == mock_repo


def test_get_file_content_success(temp_cache_dir):
    """Test successful file content extraction using git show."""
    from plugins.syscalls.kernel_repo_manager import get_file_content

    mock_repo = Mock()
    mock_repo.git.show.return_value = "file content here"

    content = get_file_content(mock_repo, "v5.15", "arch/x86/entry/syscalls/syscall_64.tbl")

    mock_repo.git.show.assert_called_once_with("v5.15:arch/x86/entry/syscalls/syscall_64.tbl")
    assert content == "file content here"


def test_get_file_content_file_not_found(temp_cache_dir):
    """Test file not found error handling."""
    from git.exc import GitCommandError

    from plugins.syscalls.exceptions import SyscallFileNotFoundError
    from plugins.syscalls.kernel_repo_manager import get_file_content

    mock_repo = Mock()
    # Error message should not contain version to be detected as file error
    mock_repo.git.show.side_effect = GitCommandError(
        "show", 128, "path 'arch/x86/entry/syscalls/syscall_64.tbl' does not exist"
    )

    with pytest.raises(
        SyscallFileNotFoundError, match="File arch/x86/entry/syscalls/syscall_64.tbl not found in version v5.15"
    ):
        get_file_content(mock_repo, "v5.15", "arch/x86/entry/syscalls/syscall_64.tbl")


def test_get_syscall_files_post_2011():
    """Test getting syscall file contents for post-2011 kernels."""
    from plugins.syscalls.kernel_repo_manager import get_syscall_files

    mock_repo = Mock()
    mock_repo.git.show.side_effect = [
        "# syscall table content",  # syscall_64.tbl
        "/* syscalls.h content */",  # syscalls.h
    ]

    table_content, header_content = get_syscall_files(mock_repo, "v5.15")

    expected_calls = [(("v5.15:arch/x86/entry/syscalls/syscall_64.tbl",),), (("v5.15:include/linux/syscalls.h",),)]
    assert mock_repo.git.show.call_args_list == expected_calls
    assert table_content == "# syscall table content"
    assert header_content == "/* syscalls.h content */"


def test_get_syscall_files_pre_2011_fallback():
    """Test fallback to pre-2011 syscall file locations."""
    from git.exc import GitCommandError

    from plugins.syscalls.exceptions import PreKernel2011Error
    from plugins.syscalls.kernel_repo_manager import get_syscall_files

    mock_repo = Mock()
    # First call (post-2011 location) fails, second succeeds
    mock_repo.git.show.side_effect = [
        GitCommandError("show", 128, "does not exist"),  # post-2011 location fails
        "/* syscalls.h content */",  # syscalls.h succeeds
    ]

    with pytest.raises(PreKernel2011Error, match="Kernel v2.6.32 predates 2011 syscall table format"):
        get_syscall_files(mock_repo, "v2.6.32")

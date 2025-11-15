"""Kernel repository management using git show for blob extraction."""

import git
from pathlib import Path
from git.exc import GitCommandError
from .exceptions import KernelVersionNotFoundError, PreKernel2011Error, SyscallFileNotFoundError


def ensure_kernel_repo(cache_dir: str) -> git.Repo:
    """Ensure Linux kernel repository exists in cache directory.

    Args:
        cache_dir: Cache directory path

    Returns:
        Git repository object
    """
    cache_path = Path(cache_dir)
    linux_path = cache_path / "linux"

    if linux_path.exists() and (linux_path / ".git").exists():
        # Repository already exists, open it
        return git.Repo(linux_path)
    else:
        # Clone the repository
        return git.Repo.clone_from("https://github.com/torvalds/linux.git", linux_path)


def get_file_content(repo: git.Repo, version: str, file_path: str) -> str:
    """Get file content at specific version using git show.

    Args:
        repo: Git repository object
        version: Git tag/commit like 'v5.15'
        file_path: File path relative to repo root

    Returns:
        File content as string

    Raises:
        KernelVersionNotFoundError: If kernel version doesn't exist
        SyscallFileNotFoundError: If file doesn't exist at that version
    """
    try:
        return repo.git.show(f"{version}:{file_path}")
    except GitCommandError as e:
        error_str = str(e)
        # Check for invalid revision/version
        if "bad revision" in error_str.lower() or "unknown revision" in error_str.lower():
            raise KernelVersionNotFoundError(f"Kernel version {version} not found in repository")
        # Check for path not found in tree
        elif "path" in error_str and "not in" in error_str:
            raise SyscallFileNotFoundError(f"File {file_path} not found in version {version}")
        # Check for other "does not exist" errors
        elif "does not exist" in error_str:
            if version in error_str:
                raise KernelVersionNotFoundError(f"Kernel version {version} not found in repository")
            else:
                raise SyscallFileNotFoundError(f"File {file_path} not found in version {version}")
        # Re-raise original error if we can't classify it
        raise


def get_syscall_files(repo: git.Repo, version: str) -> tuple[str, str]:
    """Get syscall table and header file contents for a kernel version.

    Args:
        repo: Git repository object
        version: Kernel version like 'v5.15'

    Returns:
        Tuple of (table_content, header_content)

    Raises:
        PreKernel2011Error: If kernel predates 2011 syscall table format
        KernelVersionNotFoundError: If kernel version doesn't exist  
        SyscallFileNotFoundError: If syscall files don't exist
    """
    # Try post-2011 location first
    table_path = "arch/x86/entry/syscalls/syscall_64.tbl"
    header_path = "include/linux/syscalls.h"

    try:
        table_content = get_file_content(repo, version, table_path)
        header_content = get_file_content(repo, version, header_path)
        return table_content, header_content
    except SyscallFileNotFoundError as e:
        # Check if it's a pre-2011 kernel (no .tbl files)
        if table_path in str(e):
            try:
                # Try to get syscalls.h to see if the version exists
                get_file_content(repo, version, header_path)
                # If syscalls.h exists but .tbl doesn't, it's pre-2011
                raise PreKernel2011Error(f"Kernel {version} predates 2011 syscall table format")
            except (SyscallFileNotFoundError, KernelVersionNotFoundError):
                # Neither file exists - version might be invalid  
                raise KernelVersionNotFoundError(f"Kernel version {version} not found")
        raise

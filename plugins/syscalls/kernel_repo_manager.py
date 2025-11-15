"""Kernel repository management using git show for blob extraction."""

import git
from pathlib import Path
from git.exc import GitCommandError


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
        return git.Repo.clone_from(
            "https://github.com/torvalds/linux.git",
            linux_path
        )


def get_file_content(repo: git.Repo, version: str, file_path: str) -> str:
    """Get file content at specific version using git show.
    
    Args:
        repo: Git repository object
        version: Git tag/commit like 'v5.15'
        file_path: File path relative to repo root
        
    Returns:
        File content as string
        
    Raises:
        FileNotFoundError: If file doesn't exist at that version
    """
    try:
        return repo.git.show(f"{version}:{file_path}")
    except GitCommandError as e:
        if "does not exist" in str(e):
            raise FileNotFoundError(f"File {file_path} not found in version {version}")
        raise


def get_syscall_files(repo: git.Repo, version: str) -> tuple[str, str]:
    """Get syscall table and header file contents for a kernel version.
    
    Args:
        repo: Git repository object
        version: Kernel version like 'v5.15'
        
    Returns:
        Tuple of (table_content, header_content)
        
    Raises:
        ValueError: If pre-2011 kernel (not implemented)
        FileNotFoundError: If files don't exist
    """
    # Try post-2011 location first
    table_path = "arch/x86/entry/syscalls/syscall_64.tbl"
    header_path = "include/linux/syscalls.h"
    
    try:
        table_content = get_file_content(repo, version, table_path)
        header_content = get_file_content(repo, version, header_path)
        return table_content, header_content
    except FileNotFoundError:
        # Check if it's a pre-2011 kernel
        try:
            # Try to get syscalls.h to see if the version exists
            get_file_content(repo, version, header_path)
            # If syscalls.h exists but .tbl doesn't, it's pre-2011
            raise ValueError("Pre-2011 kernel syscall extraction not implemented")
        except FileNotFoundError:
            # Neither file exists - version might be invalid
            raise FileNotFoundError("Syscall table file not found")
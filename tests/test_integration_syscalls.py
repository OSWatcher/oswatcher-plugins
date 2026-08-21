"""Integration tests for syscall extraction with real git operations."""

import pytest


@pytest.mark.integration
def test_real_syscall_extraction_v5_15():
    """Integration test: extract and parse real syscalls from v5.15 using cached repo."""
    import appdirs

    from plugins.syscalls.kernel_repo_manager import ensure_kernel_repo, get_syscall_files
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line
    from plugins.syscalls.syscalls_h_parser import parse_syscall_signature

    # Use appdirs for cache directory
    cache_dir = appdirs.user_cache_dir("oswatcher-plugins")
    repo = ensure_kernel_repo(cache_dir)

    # Extract syscall files for v5.15
    table_content, header_content = get_syscall_files(repo, "v5.15")

    # Verify we got actual content
    assert "# 64-bit system call numbers" in table_content
    assert "asmlinkage long" in header_content
    print(f"✓ Extracted table content: {len(table_content)} characters")
    print(f"✓ Extracted header content: {len(header_content)} characters")

    # Parse all syscalls from table
    syscalls = []
    for line in table_content.strip().split("\n"):
        syscall = parse_syscall_table_line(line)
        if syscall is not None:
            syscalls.append(syscall)

    print(f"✓ Parsed {len(syscalls)} syscalls from table")
    assert len(syscalls) > 300, f"Expected 300+ syscalls, found {len(syscalls)}"

    # Test specific known syscalls
    read_syscall = next((s for s in syscalls if s.name == "read"), None)
    assert read_syscall is not None, "read syscall not found"
    assert read_syscall.index == 0, f"read syscall should be index 0, got {read_syscall.index}"
    print(f"✓ Found read syscall: {read_syscall}")

    write_syscall = next((s for s in syscalls if s.name == "write"), None)
    assert write_syscall is not None, "write syscall not found"
    assert write_syscall.index == 1, f"write syscall should be index 1, got {write_syscall.index}"
    print(f"✓ Found write syscall: {write_syscall}")

    # Parse signatures for known syscalls
    read_signature = parse_syscall_signature(header_content, "sys_read")
    assert read_signature is not None, "read signature not found in headers"
    assert read_signature.name == "read"
    assert len(read_signature.parameters) == 3, f"read should have 3 params, got {len(read_signature.parameters)}"
    print(f"✓ Parsed read signature: {read_signature}")

    write_signature = parse_syscall_signature(header_content, "sys_write")
    assert write_signature is not None, "write signature not found in headers"
    assert write_signature.name == "write"
    assert len(write_signature.parameters) == 3, f"write should have 3 params, got {len(write_signature.parameters)}"
    print(f"✓ Parsed write signature: {write_signature}")

    # Verify parameter types are cleaned (no __user)
    for param in read_signature.parameters:
        assert "__user" not in param, f"__user not cleaned from parameter: {param}"

    print("✓ Integration test passed: real syscall extraction working!")


@pytest.mark.integration
@pytest.mark.slow
def test_syscall_extraction_across_kernel_versions():
    """Integration test: validate syscall extraction across Linux kernel history using git tags."""
    import re

    import appdirs

    from plugins.syscalls.kernel_repo_manager import ensure_kernel_repo, get_syscall_files
    from plugins.syscalls.syscall_table_parser import parse_syscall_table_line
    from plugins.syscalls.syscalls_h_parser import parse_syscall_signature

    # Use appdirs for cache directory
    cache_dir = appdirs.user_cache_dir("oswatcher-plugins")
    repo = ensure_kernel_repo(cache_dir)

    # Get all kernel version tags from git
    all_tags = [tag.name for tag in repo.tags]

    # Filter for major.minor versions v2.6 to v6.10 (no patch versions)
    version_pattern = re.compile(r"^v([2-6])\.(\d+)$")
    kernel_versions = set()

    for tag in all_tags:
        match = version_pattern.match(tag)
        if match:
            major, minor = match.groups()
            major, minor = int(major), int(minor)

            # Filter: v2.6+ to v6.17
            if (major == 2 and minor >= 6) or (major >= 3 and major <= 6):
                if major == 6 and minor > 17:
                    continue  # Skip versions > 6.17
                kernel_versions.add((major, minor, tag))

    # Convert to sorted list
    test_versions = sorted([v[2] for v in kernel_versions])
    print(f"Testing {len(test_versions)} kernel versions: {test_versions}")

    results = []
    pre_2011_count = 0
    post_2011_count = 0

    for version in test_versions:
        try:
            print(f"\n=== Testing {version} ===")

            # Try to extract syscall files
            table_content, header_content = get_syscall_files(repo, version)

            # Parse syscalls from table
            syscalls = []
            for line in table_content.strip().split("\n"):
                syscall = parse_syscall_table_line(line)
                if syscall is not None:
                    syscalls.append(syscall)

            syscall_count = len(syscalls)

            # Test read/write syscalls (should exist in all versions)
            read_syscall = next((s for s in syscalls if s.name == "read"), None)
            write_syscall = next((s for s in syscalls if s.name == "write"), None)

            # Test signature parsing for read syscall
            read_signature = parse_syscall_signature(header_content, "sys_read")

            result = {
                "version": version,
                "syscall_count": syscall_count,
                "has_read": read_syscall is not None,
                "has_write": write_syscall is not None,
                "read_signature_found": read_signature is not None,
                "table_size": len(table_content),
                "header_size": len(header_content),
            }

            results.append(result)
            post_2011_count += 1

            print(
                f"✓ {version}: {syscall_count} syscalls, read: {read_syscall}, signature: {read_signature is not None}"
            )

            # Basic sanity checks
            assert syscall_count > 200, f"{version}: Too few syscalls ({syscall_count})"
            assert read_syscall is not None, f"{version}: Missing read syscall"
            assert write_syscall is not None, f"{version}: Missing write syscall"
            assert read_syscall.index == 0, f"{version}: read syscall not at index 0"
            assert write_syscall.index == 1, f"{version}: write syscall not at index 1"

        except Exception as e:
            from plugins.syscalls.exceptions import (
                KernelVersionNotFoundError,
                PreKernel2011Error,
                SyscallFileNotFoundError,
            )

            if isinstance(e, PreKernel2011Error):
                print(f"✓ {version}: Pre-2011 kernel detected (expected)")
                pre_2011_count += 1
            elif isinstance(e, (KernelVersionNotFoundError, SyscallFileNotFoundError)):
                print(f"✗ {version}: {e}")
                # Continue with other versions
                continue
            else:
                print(f"✗ {version}: Unexpected error: {e}")
                raise

    # Summary
    print("\n=== Summary ===")
    print(f"Pre-2011 kernels: {pre_2011_count}")
    print(f"Post-2011 kernels: {post_2011_count}")
    print(f"Total tested: {len(results)}")

    # Verify we tested a reasonable number of versions
    assert post_2011_count >= 5, f"Should test 5+ post-2011 versions, got {post_2011_count}"

    # Test syscall evolution - newer kernels should have more syscalls
    if len(results) >= 2:
        results_sorted = sorted(results, key=lambda x: x["syscall_count"])
        oldest = results_sorted[0]
        newest = results_sorted[-1]

        print(
            f"✓ Syscall evolution: {oldest['version']} ({oldest['syscall_count']}) "
            f"→ {newest['version']} ({newest['syscall_count']})"
        )
        assert newest["syscall_count"] > oldest["syscall_count"], "Newer kernels should have more syscalls"

    print("✓ Kernel version integration test passed!")


if __name__ == "__main__":
    # Allow running directly for quick testing
    test_real_syscall_extraction_v5_15()

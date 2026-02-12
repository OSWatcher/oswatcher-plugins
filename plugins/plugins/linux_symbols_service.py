"""Pure functions for Linux kernel symbol extraction.

This module provides pure functions for:
- Constructing ddebs.ubuntu.com URLs for debug packages
- Parsing kernel version strings
- Extracting vmlinux from ddeb archives
- Parsing DWARF debug info via dwarf2json (Volatility Foundation Go binary)
"""

from __future__ import annotations

import gzip
import hashlib
import json
import lzma
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import requests

if TYPE_CHECKING:
    from neogit.model.merkle import Tree


# Pattern: vmlinuz-{major}.{minor}.{patch}-{build}-{flavor}
# Example: vmlinuz-6.8.0-45-generic -> ("6.8.0", "45", "generic")
KERNEL_VERSION_PARTS_PATTERN = re.compile(r"^vmlinuz-(\d+\.\d+\.\d+)-(\d+)-(.+)$")


def parse_kernel_version_parts(filename: str) -> Tuple[str, str, str]:
    """Parse vmlinuz filename into version components.

    Args:
        filename: Kernel filename like "vmlinuz-6.8.0-45-generic"

    Returns:
        Tuple of (version, build, flavor) e.g., ("6.8.0", "45", "generic")

    Raises:
        ValueError: If filename format is invalid
    """
    match = KERNEL_VERSION_PARTS_PATTERN.match(filename)
    if not match:
        raise ValueError(f"Invalid kernel filename format: {filename}")

    return match.groups()  # type: ignore


def construct_ddeb_url(kernel_version: str, build: str, flavor: str, arch: str) -> str:
    """Construct ddebs.ubuntu.com URL for debug package.

    The URL pattern is:
    http://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-{version}-{build}-{flavor}-dbgsym_{version}-{build}.{build}_{arch}.ddeb

    Args:
        kernel_version: Kernel version like "6.8.0"
        build: Build number like "45"
        flavor: Kernel flavor like "generic"
        arch: Architecture like "amd64"

    Returns:
        Full URL to the ddeb package

    Example:
        >>> construct_ddeb_url("6.8.0", "45", "generic", "amd64")
        'http://ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-6.8.0-45-generic-dbgsym_6.8.0-45.45_amd64.ddeb'
    """
    # Format: linux-image-unsigned-{ver}-{build}-{flavor}-dbgsym_{ver}-{build}.{build}_{arch}.ddeb
    package_name = f"linux-image-unsigned-{kernel_version}-{build}-{flavor}-dbgsym"
    version_string = f"{kernel_version}-{build}.{build}"
    filename = f"{package_name}_{version_string}_{arch}.ddeb"

    base_url = "http://ddebs.ubuntu.com/pool/main/l/linux"
    return f"{base_url}/{filename}"


def _parse_packages_index_for_filename(index_content: str, package_names: List[str], arch: str) -> Optional[str]:
    """Parse Debian Packages index and return matching ddeb filename."""
    package_set = set(package_names)
    fields: Dict[str, str] = {}

    def match_current_stanza() -> Optional[str]:
        if fields.get("Package") not in package_set:
            return None
        if fields.get("Architecture") != arch:
            return None
        filename = fields.get("Filename")
        if filename and filename.endswith(".ddeb"):
            return filename
        return None

    for line in index_content.splitlines():
        if not line.strip():
            filename = match_current_stanza()
            if filename:
                return filename
            fields = {}
            continue

        if line.startswith(" "):
            continue

        key, sep, value = line.partition(":")
        if not sep:
            continue
        fields[key] = value.strip()

    return match_current_stanza()


def resolve_ddeb_url_from_packages(
    kernel_version: str,
    build: str,
    flavor: str,
    arch: str,
    codename: Optional[str],
    timeout: int = 30,
) -> Optional[str]:
    """Resolve exact ddeb URL by scanning ddebs Packages indexes.

    This avoids brittle assumptions about package revision numbers.
    """
    base_hosts = ["http://ddebs.ubuntu.com", "https://ddebs.ubuntu.com"]
    package_names = [
        f"linux-image-unsigned-{kernel_version}-{build}-{flavor}-dbgsym",
        f"linux-image-{kernel_version}-{build}-{flavor}-dbgsym",
    ]
    fallback_codenames = ["noble", "oracular", "plucky", "jammy", "focal"]
    codenames: List[str] = []
    if codename:
        codenames.append(codename)
    codenames.extend([x for x in fallback_codenames if x not in codenames])
    suites = []
    for release in codenames:
        suites.extend([release, f"{release}-updates", f"{release}-security", f"{release}-proposed"])
    components = ["main", "restricted", "universe", "multiverse"]
    index_variants = ["Packages.xz", "Packages.gz", "Packages"]

    for base_url in base_hosts:
        for suite in suites:
            for component in components:
                for index_name in index_variants:
                    index_url = f"{base_url}/dists/{suite}/{component}/binary-{arch}/{index_name}"
                    try:
                        response = requests.get(index_url, timeout=timeout)
                        response.raise_for_status()
                    except requests.RequestException:
                        continue

                    try:
                        if index_name.endswith(".xz"):
                            content = lzma.decompress(response.content).decode("utf-8", errors="replace")
                        elif index_name.endswith(".gz"):
                            content = gzip.decompress(response.content).decode("utf-8", errors="replace")
                        else:
                            content = response.text
                    except (lzma.LZMAError, gzip.BadGzipFile, UnicodeDecodeError):
                        continue

                    filename = _parse_packages_index_for_filename(content, package_names, arch)
                    if filename:
                        return f"{base_url}/{filename.lstrip('/')}"

    # Fallback: scan pool directory listing directly.
    pool_url = _resolve_ddeb_url_from_pool_listing(kernel_version, build, flavor, arch, timeout)
    if pool_url:
        return pool_url

    return None


def _resolve_ddeb_url_from_pool_listing(
    kernel_version: str,
    build: str,
    flavor: str,
    arch: str,
    timeout: int = 30,
) -> Optional[str]:
    """Resolve ddeb URL by matching filenames in the pool directory listing."""
    pool_urls = [
        "http://ddebs.ubuntu.com/pool/main/l/linux/",
        "http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/",
        "https://ddebs.ubuntu.com/pool/main/l/linux/",
        "https://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/",
    ]
    package_prefixes = [
        f"linux-image-unsigned-{kernel_version}-{build}-{flavor}-dbgsym_",
        f"linux-image-{kernel_version}-{build}-{flavor}-dbgsym_",
    ]

    for pool_url in pool_urls:
        try:
            response = requests.get(pool_url, timeout=timeout)
            response.raise_for_status()
            html = response.text
        except requests.RequestException:
            continue

        matches = []
        for prefix in package_prefixes:
            pattern = rf'href="({re.escape(prefix)}[^"]*_{re.escape(arch)}\.ddeb)"'
            matches.extend(re.findall(pattern, html))

        if matches:
            # Keep deterministic behavior and prefer highest lexical revision.
            filename = sorted(set(matches))[-1]
            return f"{pool_url}{filename}"

    return None


def detect_ubuntu_codename(root_tree: "Tree") -> Optional[str]:
    """Extract Ubuntu codename from /etc/os-release in filesystem.

    Args:
        root_tree: Root filesystem tree

    Returns:
        Ubuntu codename like "noble", "jammy", or None if not found
    """
    try:
        os_release = root_tree.get_child_at_path(PurePath("/etc/os-release"))
        if hasattr(os_release, "content"):
            content = os_release.content.decode("utf-8", errors="replace")
            for line in content.splitlines():
                if line.startswith("VERSION_CODENAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except (FileNotFoundError, AttributeError):
        pass
    return None


def extract_vmlinux_from_ddeb(ddeb_path: Path, output_dir: Path) -> Path:
    """Extract vmlinux from ddeb archive.

    ddeb structure:
      - ddeb is an ar archive
      - Contains data.tar.xz (or data.tar.zst)
      - vmlinux is at usr/lib/debug/boot/vmlinux-*

    Args:
        ddeb_path: Path to downloaded ddeb file
        output_dir: Directory to extract vmlinux to

    Returns:
        Path to extracted vmlinux file

    Raises:
        ValueError: If vmlinux not found in archive
    """
    # Extract data.tar from ar archive using ar command
    # ar archives are simple and ar is universally available
    result = subprocess.run(
        ["ar", "-t", str(ddeb_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    archive_members = result.stdout.strip().split("\n")

    # Find data.tar.* file
    data_tar_name = None
    for member in archive_members:
        if member.startswith("data.tar"):
            data_tar_name = member
            break

    if not data_tar_name:
        raise ValueError(f"No data.tar found in ddeb: {ddeb_path}")

    # Extract data.tar to temp location
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        subprocess.run(
            ["ar", "-x", str(ddeb_path), data_tar_name],
            cwd=tmpdir_path,
            check=True,
        )

        data_tar_path = tmpdir_path / data_tar_name

        # Open data.tar (handles .xz, .zst, .gz transparently)
        with tarfile.open(data_tar_path, "r:*") as tar:
            # Find vmlinux file
            vmlinux_member: Optional[tarfile.TarInfo] = None
            tar_members: List[tarfile.TarInfo] = tar.getmembers()
            for tar_entry in tar_members:
                if tar_entry.name.endswith("/vmlinux") or "/boot/vmlinux-" in tar_entry.name:
                    if tar_entry.isfile():
                        vmlinux_member = tar_entry
                        break

            if vmlinux_member is None:
                # List all members for debugging
                members_list = [m.name for m in tar_members][:20]
                raise ValueError(f"Could not find vmlinux in ddeb. Members: {members_list}")

            # Extract vmlinux
            vmlinux_member.name = Path(vmlinux_member.name).name  # Flatten path
            tar.extract(vmlinux_member, path=output_dir)
            return output_dir / vmlinux_member.name


# --- DWARF/Symbol Parsing with dwarf2json ---


def run_dwarf2json(vmlinux_path: Path) -> Dict[str, Any]:
    """Run dwarf2json on vmlinux and return parsed ISF JSON.

    dwarf2json is a Go binary from the Volatility Foundation that extracts
    DWARF debug info into the Volatility3 Intermediate Symbol Format (ISF).

    Args:
        vmlinux_path: Path to vmlinux ELF file with debug symbols

    Returns:
        Dictionary with keys: "symbols", "user_types", "enums", "base_types", "metadata"

    Raises:
        FileNotFoundError: If dwarf2json binary is not found on PATH
        RuntimeError: If dwarf2json exits with non-zero status
    """
    try:
        proc = subprocess.Popen(
            ["dwarf2json", "linux", "--elf", str(vmlinux_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "dwarf2json not found on PATH. " "Install from https://github.com/volatilityfoundation/dwarf2json"
        )

    stdout_bytes, stderr_bytes = proc.communicate()

    if proc.returncode != 0:
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        raise RuntimeError(f"dwarf2json failed with exit code {proc.returncode}: {stderr}")

    return json.loads(stdout_bytes)


def parse_symbols_for_neo4j(symbols_dict: Dict[str, Dict]) -> List[Dict[str, str]]:
    """Convert parsed ELF symbols to Neo4j-compatible format.

    Args:
        symbols_dict: Dictionary from parse_elf_symbols()

    Returns:
        List of symbol dictionaries with sym_name, address, and hash fields
    """
    entries = []
    for sym, value in sorted(symbols_dict.items()):
        # Skip internal/compiler symbols
        if sym.startswith("__"):
            continue

        address = str(value["address"])
        entries.append(
            {
                "sym_name": sym,
                "address": address,
                "hash": hashlib.sha1(address.encode()).hexdigest(),
            }
        )

    return entries

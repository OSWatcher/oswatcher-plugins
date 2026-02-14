"""Linux kernel symbol extraction plugin using DWARF debug info from Ubuntu ddebs."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import requests
from attrs import define, field
from neogit.model.neo import Commit

from plugins.plugins.linux_symbols_service import (
    detect_ubuntu_codename,
    extract_vmlinux_from_ddeb,
    parse_kernel_version_parts,
    parse_symbols_for_neo4j,
    resolve_ddeb_url_from_packages,
    run_dwarf2json,
)
from plugins.plugins.symbols import DataTypeMerkleNode, StructMerkleNode, StructNode, SymbolsMerkleVisitor
from plugins.plugins.symbols_repository import SymbolsRepository
from plugins.syscalls.filesystem import KernelInfo, find_kernel_versions, get_boot_directory
from plugins.types import AbstractPlugin, UniqueConstraint


def lief_arch_to_ddeb_arch(lief_arch: str) -> str:
    """Convert lief architecture string to ddeb architecture name.

    Handles both ELF machine types (e.g., "ARCH.x86_64") and
    PE machine types from EFI boot stubs (e.g., "MACHINE_TYPES.AMD64").

    Args:
        lief_arch: Architecture string from lief

    Returns:
        Architecture for ddeb URL like "amd64" or "arm64"
    """
    arch_lower = lief_arch.lower()
    if "x86_64" in arch_lower or "amd64" in arch_lower:
        return "amd64"
    if "aarch64" in arch_lower or "arm64" in arch_lower:
        return "arm64"
    if "arm" in arch_lower:
        return "armhf"
    if "i386" in arch_lower or "i686" in arch_lower:
        return "i386"
    raise ValueError(f"Unrecognized architecture: {lief_arch!r}")


@define(auto_attribs=True)
class LinuxSymbolsPlugin(AbstractPlugin):
    """Plugin to extract Linux kernel symbols and struct definitions from DWARF debug info.

    This plugin:
    1. Finds Linux kernels in /boot directory
    2. Downloads debug symbols from ddebs.ubuntu.com
    3. Parses DWARF debug info using dwarf2json (Volatility Foundation)
    4. Stores symbols and struct definitions in Neo4j
    """

    _repository: Optional[SymbolsRepository] = field(init=False, default=None)

    # Request timeout for downloading ddeb packages (in seconds)
    DOWNLOAD_TIMEOUT = 300

    @property
    def repository(self) -> SymbolsRepository:
        """Lazy-initialize repository."""
        if self._repository is None:
            self._repository = SymbolsRepository(self.neogit)
        return self._repository

    def constraints_data(self) -> List[UniqueConstraint]:
        """Return constraints for symbol-related nodes.

        Reuses same constraints as SymbolsPlugin since we use the same node types.
        """
        return [
            UniqueConstraint(label="Symbol", property_list=["hash"]),
            UniqueConstraint(label="Struct", property_list=["hash"]),
            UniqueConstraint(label="StructField", property_list=["hash"]),
            UniqueConstraint(label="DataType", property_list=["hash"]),
        ]

    def run(self, commit: Commit):
        """Execute Linux symbol extraction for a commit.

        Args:
            commit: The Commit node to analyze
        """
        self.logger.info(f"Running Linux symbols plugin for commit {commit.hash}")

        # Get the root filesystem tree
        try:
            root_tree = commit.filesystem[0]
        except IndexError:
            self.logger.warning(f"No filesystem found for commit {commit.hash}")
            return

        # Navigate to /boot directory
        boot_tree = get_boot_directory(root_tree)
        if not boot_tree:
            self.logger.info("No /boot directory found, skipping Linux symbol extraction")
            return

        codename = detect_ubuntu_codename(root_tree)
        if codename:
            self.logger.info(f"Detected Ubuntu codename: {codename}")
        else:
            self.logger.warning("Could not detect Ubuntu codename from /etc/os-release")

        # Find kernel versions from vmlinuz files
        kernel_info_list = find_kernel_versions(boot_tree, self)
        if not kernel_info_list:
            self.logger.info("No kernel files found in /boot")
            return

        self.logger.info(
            f"Found {len(kernel_info_list)} kernel(s): "
            + ", ".join(f"{k.filename} ({k.architecture})" for k in kernel_info_list)
        )

        # Process each kernel
        for kernel_info in kernel_info_list:
            try:
                self._process_kernel(kernel_info, codename)
            except Exception:
                self.logger.exception(f"Failed to process kernel {kernel_info.filename}")

        self.logger.info(f"Linux symbol extraction complete for commit {commit.hash}")

    def _process_kernel(self, kernel_info: KernelInfo, codename: Optional[str]):
        """Process a single kernel: download debug symbols and extract info.

        Args:
            kernel_info: Information about the kernel to process
        """
        self.logger.info(f"Processing kernel: {kernel_info.filename}")

        # Parse version components from filename
        try:
            version, build, flavor = parse_kernel_version_parts(kernel_info.filename)
        except ValueError as e:
            self.logger.warning(f"Cannot parse kernel version from {kernel_info.filename}: {e}")
            return

        # Convert architecture
        ddeb_arch = lief_arch_to_ddeb_arch(kernel_info.architecture)

        # Resolve exact ddeb URL from repository metadata.
        ddeb_url = resolve_ddeb_url_from_packages(version, build, flavor, ddeb_arch, codename)
        if ddeb_url is None:
            self.logger.error(
                f"Could not resolve debug package URL for {kernel_info.filename} "
                f"(codename={codename}, arch={ddeb_arch})"
            )
            return

        self.logger.info(f"Debug package URL: {ddeb_url}")

        # Download and process ddeb
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Download ddeb
            ddeb_path = tmpdir_path / "debug.ddeb"
            try:
                self._download_ddeb(ddeb_url, ddeb_path)
            except Exception as e:
                self.logger.error(f"Failed to download ddeb from {ddeb_url}: {e}")
                return

            # Extract vmlinux
            try:
                vmlinux_path = extract_vmlinux_from_ddeb(ddeb_path, tmpdir_path)
                self.logger.info(f"Extracted vmlinux: {vmlinux_path}")
            except Exception as e:
                self.logger.error(f"Failed to extract vmlinux: {e}")
                return

            # Parse everything in one dwarf2json call
            try:
                self.logger.info("Running dwarf2json...")
                dwarf_data = run_dwarf2json(vmlinux_path)
            except Exception as e:
                self.logger.error(f"Failed to run dwarf2json: {e}")
                return

            # Insert symbols
            symbols_dict = dwarf_data.get("symbols", {})
            self.logger.info(f"Found {len(symbols_dict)} symbols")
            param_list = parse_symbols_for_neo4j(symbols_dict)
            self.logger.info(f"Inserting {len(param_list)} symbols into Neo4j")
            self.repository.insert_symbols(kernel_info.blob_hash, param_list)

            # Insert enums
            enums = dwarf_data.get("enums", {})
            self.logger.info(f"Found {len(enums)} enums")
            count_enum = self._insert_user_types(kernel_info.blob_hash, enums)

            # Insert structs/unions
            types = dwarf_data.get("user_types", {})
            self.logger.info(f"Found {len(types)} struct/union types")
            count_types = self._insert_user_types(kernel_info.blob_hash, types)

            self.logger.info(f"Inserted {len(param_list)} symbols, {count_enum} enums, {count_types} types")

    def _download_ddeb(self, url: str, output_path: Path):
        """Download ddeb package from URL.

        Args:
            url: URL to download from
            output_path: Path to save the downloaded file
        """
        self.logger.info(f"Downloading: {url}")

        response = requests.get(url, timeout=self.DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    if downloaded % (10 * 1024 * 1024) < 8192:  # Log every ~10MB
                        mb_downloaded = downloaded / 1024 / 1024
                        self.logger.debug(f"Downloaded {mb_downloaded:.1f}MB ({percent:.1f}%)")  # noqa: E231

        mb_downloaded = downloaded / 1024 / 1024
        self.logger.info(f"Downloaded {mb_downloaded:.1f}MB to {output_path}")  # noqa: E231

    def _insert_user_types(self, blob_hash: str, types_dict: Dict) -> int:
        """Insert user types (structs/unions/enums) into Neo4j using Merkle visitor.

        This method reuses the same logic as SymbolsPlugin.parse_users_types().

        Args:
            blob_hash: Hash of the kernel blob
            types_dict: Dictionary of type definitions in volatility3 format

        Returns:
            Number of types processed
        """
        with SymbolsMerkleVisitor(thread=True) as visitor:
            for struct_name, struct_data in sorted(types_dict.items()):
                self.logger.debug(f"Processing type: {struct_name}")
                struct_node = StructNode(name=struct_name, struct_data=struct_data)
                visitor.run_visit(struct_node)

                for node in visitor.as_gen():
                    merkle_node = node.return_value
                    if isinstance(merkle_node, DataTypeMerkleNode):
                        self.repository.insert_data_type(merkle_node)
                    if isinstance(merkle_node, StructMerkleNode):
                        unwind_param = [
                            {
                                "hash": child_node.hash,
                                "name": child_name,
                                "offset": child_node.offset,
                                "data_type": child_node.data_type,
                            }
                            for child_name, child_node in merkle_node.children.items()
                        ]
                        self.repository.insert_struct(blob_hash, merkle_node, unwind_param)

        return len(types_dict)

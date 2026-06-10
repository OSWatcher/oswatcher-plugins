# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

"""Linux syscall extraction plugin using kernel filesystem analysis and Git repository."""

from typing import Dict, List

import appdirs
from attrs import define
from neogit.model.neo import Commit

from plugins.syscalls.exceptions import KernelVersionNotFoundError, PreKernel2011Error, SyscallFileNotFoundError
from plugins.syscalls.filesystem import KernelInfo, find_kernel_versions, get_boot_directory
from plugins.syscalls.kernel_repo_manager import ensure_kernel_repo, get_syscall_files
from plugins.syscalls.nodes import SyscallsMerkleVisitor, SyscallTableNode
from plugins.syscalls.syscall_table_parser import parse_syscall_table_line
from plugins.syscalls.syscalls_h_parser import parse_syscall_signature
from plugins.types import AbstractPlugin


@define(auto_attribs=True)
class SyscallsPlugin(AbstractPlugin):
    """Plugin to extract Linux syscall information from kernel files.

    This plugin:
    1. Navigates to /boot directory using new Tree API
    2. Finds vmlinuz kernel files
    3. Parses kernel versions
    4. Fetches syscall information from Linux kernel Git repository
    5. Extracts syscall signatures with parameters
    """

    def run(self, commit: Commit):
        """Execute syscall extraction for a commit.

        Args:
            commit: The Commit node to analyze
        """
        self.logger.info(f"Running syscall plugin for commit {commit.hash}")

        # Get the root filesystem tree
        try:
            root_tree = commit.filesystem[0]
        except IndexError:
            self.logger.warning(f"No filesystem found for commit {commit.hash}")
            return

        # Navigate to /boot directory - using public function
        boot_tree = get_boot_directory(root_tree)
        if not boot_tree:
            self.logger.info("No /boot directory found, skipping syscall extraction")
            return

        # Find kernel versions from vmlinuz files - using public function
        kernel_info_list = find_kernel_versions(boot_tree, self)
        if not kernel_info_list:
            self.logger.info("No kernel files found in /boot")
            return

        self.logger.info(
            f"Found {len(kernel_info_list)} kernel(s): "
            + ", ".join(f"{k.filename} ({k.architecture})" for k in kernel_info_list)
        )

        # Extract syscalls from Linux kernel repository
        syscall_data = self._extract_syscalls_from_repo(kernel_info_list)

        # Transform to Nodes and visit with MerkleVisitor
        self._transform_and_visit(kernel_info_list, syscall_data)

        self.logger.info(f"Syscall extraction complete for commit {commit.hash}")

    def _extract_syscalls_from_repo(self, kernel_info_list: List[KernelInfo]) -> Dict[str, List[dict]]:
        """Extract syscall information from Linux kernel Git repository.

        Args:
            kernel_info_list: List of kernel information to extract

        Returns:
            Dictionary mapping kernel version to list of syscall data
        """
        syscall_data = {}
        cache_dir = appdirs.user_cache_dir("oswatcher-plugins")
        self.logger.info(f"Cloning/updating Linux kernel repository to {cache_dir}")
        repo = ensure_kernel_repo(cache_dir)

        # Extract syscalls for each kernel version
        for kernel_info in kernel_info_list:
            version = kernel_info.version
            try:
                syscalls = self._extract_version_syscalls(repo, version)
                if syscalls:
                    syscall_data[version] = syscalls
                    self.logger.info(f"Extracted {len(syscalls)} syscalls for {version} ({kernel_info.architecture})")
            except PreKernel2011Error as e:
                self.logger.warning(f"Skipping {version}: {e}")
            except KernelVersionNotFoundError as e:
                self.logger.warning(f"Version {version} not found in repository: {e}")  # noqa: E713
            except SyscallFileNotFoundError as e:
                self.logger.warning(f"Syscall files not found for {version}: {e}")
            except Exception as e:
                self.logger.error(f"Failed to extract syscalls for {version}: {e}")

        return syscall_data

    def _extract_version_syscalls(self, repo, version: str) -> List[dict]:
        """Extract syscall data for a specific kernel version.

        Args:
            repo: Git repository object
            version: Kernel version like 'v5.15'

        Returns:
            List of dictionaries with syscall information
        """
        # Get syscall table and header files from repository
        table_content, header_content = get_syscall_files(repo, version)

        syscalls = []

        # Parse syscall table
        for line in table_content.splitlines():
            syscall_index = parse_syscall_table_line(line)
            if syscall_index:
                # Get signature from header file
                entry_name = f"sys_{syscall_index.name}"
                signature = parse_syscall_signature(header_content, entry_name)

                syscall_info = {
                    "name": syscall_index.name,
                    "index": syscall_index.index,
                    "entry_point": entry_name,
                }

                if signature:
                    syscall_info["parameters"] = signature.parameters
                else:
                    syscall_info["parameters"] = None
                    self.logger.debug(f"No signature found for {entry_name}")

                syscalls.append(syscall_info)

        return syscalls

    def _transform_and_visit(self, kernel_info_list: List[KernelInfo], syscall_data: Dict[str, List[dict]]):
        """Transform syscall data to Nodes and visit with MerkleVisitor.

        Args:
            kernel_info_list: List of kernel information
            syscall_data: Dictionary mapping kernel version to syscall list
        """
        if not syscall_data:
            self.logger.info("No syscall data to transform")
            return

        # Create visitor (threaded for async processing)
        with SyscallsMerkleVisitor(thread=True) as visitor:
            # Create SyscallTableNode for each kernel
            for kernel_info in kernel_info_list:
                version_data = syscall_data.get(kernel_info.version)
                if not version_data:
                    continue

                # Create SyscallTableNode
                table_node = SyscallTableNode(architecture=kernel_info.architecture, syscalls=version_data)

                # Visit to compute hashes
                self.logger.info(
                    f"Creating SyscallTableNode for {kernel_info.version} "
                    f"({kernel_info.architecture}) with {len(version_data)} syscalls"
                )
                visitor.run_visit(table_node)

            # Iterate visited nodes (includes both SyscallMerkleNodes and SyscallTableMerkleNodes)
            for visited_node in visitor.as_gen():
                merkle_node = visited_node.return_value
                # Only log SyscallTableMerkleNodes (skip individual syscall children)
                if hasattr(merkle_node, "architecture"):
                    self.logger.info(
                        f"Created SyscallTableMerkleNode: hash={merkle_node.hash[:8]}... "
                        f"arch={merkle_node.architecture} children={len(merkle_node.children)}"
                    )
                    # TODO: Insert into Neo4j (next phase)

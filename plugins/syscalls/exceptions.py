# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

"""Syscall extraction specific exceptions."""


class SyscallExtractionError(Exception):
    """Base exception for syscall extraction errors."""

    pass


class KernelVersionNotFoundError(SyscallExtractionError):
    """Kernel version does not exist in the repository."""

    pass


class PreKernel2011Error(SyscallExtractionError):
    """Kernel version predates 2011 syscall table format (not supported)."""

    pass


class SyscallFileNotFoundError(SyscallExtractionError):
    """Required syscall files not found for this kernel version."""

    pass

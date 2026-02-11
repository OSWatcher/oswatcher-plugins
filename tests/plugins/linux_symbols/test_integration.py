"""Integration tests for linux_symbols_service.py.

This module contains:
- Unit tests for pure functions (no network, fast)
- Integration tests that download actual debug packages from ddebs.ubuntu.com

Run unit tests only:
    poetry run pytest tests/plugins/linux_symbols/ -m "not integration" -v

Run integration tests (slow, ~800MB download):
    poetry run pytest tests/plugins/linux_symbols/ -m integration -v

Run all tests:
    poetry run pytest tests/plugins/linux_symbols/ -v
"""

import json
import lzma
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from plugins.plugins.linux_symbols_service import (
    _parse_packages_index_for_filename,
    construct_ddeb_url,
    extract_vmlinux_from_ddeb,
    parse_kernel_version_parts,
    parse_symbols_for_neo4j,
    resolve_ddeb_url_from_packages,
    run_dwarf2json,
)


class TestParseKernelVersionParts:
    """Unit tests for parse_kernel_version_parts (no network)."""

    def test_standard_format(self):
        """Parse standard vmlinuz filename."""
        version, build, flavor = parse_kernel_version_parts("vmlinuz-6.8.0-45-generic")
        assert version == "6.8.0"
        assert build == "45"
        assert flavor == "generic"

    def test_lowlatency_flavor(self):
        """Parse lowlatency kernel filename."""
        version, build, flavor = parse_kernel_version_parts("vmlinuz-5.15.0-100-lowlatency")
        assert version == "5.15.0"
        assert build == "100"
        assert flavor == "lowlatency"

    def test_aws_flavor(self):
        """Parse AWS-specific kernel filename."""
        version, build, flavor = parse_kernel_version_parts("vmlinuz-6.5.0-25-aws")
        assert version == "6.5.0"
        assert build == "25"
        assert flavor == "aws"

    def test_invalid_format_raises(self):
        """Should raise ValueError for invalid filename format."""
        with pytest.raises(ValueError):
            parse_kernel_version_parts("not-a-kernel")

    def test_missing_vmlinuz_prefix_raises(self):
        """Should raise ValueError when vmlinuz prefix is missing."""
        with pytest.raises(ValueError):
            parse_kernel_version_parts("6.8.0-45-generic")

    def test_incomplete_version_raises(self):
        """Should raise ValueError for incomplete version string."""
        with pytest.raises(ValueError):
            parse_kernel_version_parts("vmlinuz-6.8-45-generic")


class TestConstructDdebUrl:
    """Unit tests for construct_ddeb_url (no network)."""

    def test_standard_url_format(self):
        """Construct URL for standard generic kernel."""
        url = construct_ddeb_url("6.8.0", "45", "generic", "amd64")
        assert "ddebs.ubuntu.com" in url
        assert "6.8.0-45-generic" in url
        assert "amd64" in url
        assert url.endswith(".ddeb")

    def test_arm64_architecture(self):
        """Construct URL for ARM64 architecture."""
        url = construct_ddeb_url("6.5.0", "15", "generic", "arm64")
        assert "arm64.ddeb" in url

    def test_lowlatency_flavor(self):
        """Construct URL for lowlatency kernel."""
        url = construct_ddeb_url("5.15.0", "100", "lowlatency", "amd64")
        assert "lowlatency" in url

    def test_url_structure(self):
        """Verify complete URL structure matches ddebs.ubuntu.com pattern."""
        url = construct_ddeb_url("6.8.0", "45", "generic", "amd64")
        # Expected: ddebs.ubuntu.com/pool/main/l/linux/linux-image-unsigned-...-dbgsym_...ddeb
        assert url == (
            "http://ddebs.ubuntu.com/pool/main/l/linux/"
            "linux-image-unsigned-6.8.0-45-generic-dbgsym_6.8.0-45.45_amd64.ddeb"
        )


class TestParseSymbolsForNeo4j:
    """Unit tests for parse_symbols_for_neo4j (no network)."""

    def test_converts_symbols_to_neo4j_format(self):
        """Should convert symbol dict to Neo4j-compatible format."""
        symbols = {
            "schedule": {"address": 0x1000},
            "init_task": {"address": 0x2000},
        }

        result = parse_symbols_for_neo4j(symbols)

        assert len(result) == 2
        # Sorted by name
        assert result[0]["sym_name"] == "init_task"
        assert result[0]["address"] == "8192"  # 0x2000
        assert "hash" in result[0]

    def test_filters_dunder_symbols(self):
        """Should filter out symbols starting with __."""
        symbols = {
            "printk": {"address": 0x1000},
            "__printk_internal": {"address": 0x2000},
        }

        result = parse_symbols_for_neo4j(symbols)

        assert len(result) == 1
        assert result[0]["sym_name"] == "printk"

    def test_empty_input_returns_empty_list(self):
        """Should return empty list for empty input."""
        result = parse_symbols_for_neo4j({})
        assert result == []


class TestResolveDdebUrlFromPackages:
    """Unit tests for package index based ddeb URL resolution."""

    def test_parse_packages_index_extracts_filename(self):
        content = """
Package: linux-image-unsigned-6.14.0-37-generic-dbgsym
Architecture: amd64
Filename: pool/main/l/linux/linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb

""".strip()
        filename = _parse_packages_index_for_filename(
            content,
            ["linux-image-unsigned-6.14.0-37-generic-dbgsym"],
            "amd64",
        )
        assert filename == "pool/main/l/linux/linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb"

    def test_resolve_ddeb_url_from_packages_xz(self):
        packages = """
Package: linux-image-unsigned-6.14.0-37-generic-dbgsym
Architecture: amd64
Filename: pool/main/l/linux/linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb

""".strip()

        def fake_get(url, timeout):
            if url.endswith("/noble-updates/main/binary-amd64/Packages.xz"):
                response = MagicMock()
                response.content = lzma.compress(packages.encode("utf-8"))
                response.raise_for_status.return_value = None
                return response
            response = MagicMock()
            response.raise_for_status.side_effect = requests.HTTPError("404")
            return response

        with patch("plugins.plugins.linux_symbols_service.requests.get", side_effect=fake_get):
            url = resolve_ddeb_url_from_packages("6.14.0", "37", "generic", "amd64", "noble")

        assert url is not None
        assert "ddebs.ubuntu.com/pool/main/l/linux/" in url
        assert url.endswith("linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb")

    def test_resolve_ddeb_url_from_packages_plucky_updates(self):
        packages = """
Package: linux-image-unsigned-6.14.0-37-generic-dbgsym
Architecture: amd64
Filename: pool/main/l/linux/linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb

""".strip()

        def fake_get(url, timeout):
            if url.endswith("/plucky-updates/main/binary-amd64/Packages.xz"):
                response = MagicMock()
                response.content = lzma.compress(packages.encode("utf-8"))
                response.raise_for_status.return_value = None
                return response
            response = MagicMock()
            response.raise_for_status.side_effect = requests.HTTPError("404")
            return response

        with patch("plugins.plugins.linux_symbols_service.requests.get", side_effect=fake_get):
            url = resolve_ddeb_url_from_packages("6.14.0", "37", "generic", "amd64", "plucky")

        assert url is not None
        assert "ddebs.ubuntu.com/pool/main/l/linux/" in url
        assert url.endswith("linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb")

    def test_resolve_ddeb_url_from_packages_without_codename(self):
        packages = """
Package: linux-image-unsigned-6.14.0-37-generic-dbgsym
Architecture: amd64
Filename: pool/main/l/linux-hwe-6.14/linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.37~24.04.1_amd64.ddeb

""".strip()

        def fake_get(url, timeout):
            if url.endswith("/noble-updates/main/binary-amd64/Packages.xz"):
                response = MagicMock()
                response.content = lzma.compress(packages.encode("utf-8"))
                response.raise_for_status.return_value = None
                return response
            response = MagicMock()
            response.raise_for_status.side_effect = requests.HTTPError("404")
            return response

        with patch("plugins.plugins.linux_symbols_service.requests.get", side_effect=fake_get):
            url = resolve_ddeb_url_from_packages("6.14.0", "37", "generic", "amd64", None)

        assert url is not None
        assert "linux-hwe-6.14" in url
        assert url.endswith("linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.37~24.04.1_amd64.ddeb")

    def test_resolve_ddeb_url_from_pool_listing_fallback(self):
        html_listing = """
<a href="linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.41_amd64.ddeb">file</a>
<a href="linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.42~24.04.1_amd64.ddeb">file</a>
""".strip()

        def fake_get(url, timeout):
            if "/dists/" in url:
                response = MagicMock()
                response.raise_for_status.side_effect = requests.HTTPError("404")
                return response
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.text = html_listing
            return response

        with patch("plugins.plugins.linux_symbols_service.requests.get", side_effect=fake_get):
            url = resolve_ddeb_url_from_packages("6.14.0", "37", "generic", "amd64", "plucky")

        assert url is not None
        assert url.endswith("linux-image-unsigned-6.14.0-37-generic-dbgsym_6.14.0-37.42~24.04.1_amd64.ddeb")


class TestRunDwarf2json:
    """Unit tests for run_dwarf2json with mocked subprocess."""

    def test_parses_json_output(self):
        """Should parse dwarf2json JSON output correctly."""
        fake_output = {
            "metadata": {"producer": {"name": "dwarf2json"}},
            "symbols": {"schedule": {"address": 0x1000}},
            "user_types": {"task_struct": {"size": 9664, "kind": "struct", "fields": {}}},
            "enums": {"sock_type": {"size": 4, "constants": {"SOCK_STREAM": 1}}},
            "base_types": {"int": {"size": 4, "signed": True}},
        }

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = MagicMock()

        # json.load reads from the stdout file-like object
        import io

        mock_proc.stdout = io.BytesIO(json.dumps(fake_output).encode())

        with patch("plugins.plugins.linux_symbols_service.subprocess.Popen", return_value=mock_proc):
            result = run_dwarf2json(Path("/fake/vmlinux"))

        assert "symbols" in result
        assert "user_types" in result
        assert "enums" in result
        assert result["symbols"]["schedule"]["address"] == 0x1000
        assert result["user_types"]["task_struct"]["size"] == 9664

    def test_raises_on_nonzero_exit(self):
        """Should raise RuntimeError when dwarf2json fails."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = MagicMock()
        mock_proc.stderr.read.return_value = b"error: invalid ELF"

        import io

        mock_proc.stdout = io.BytesIO(b"{}")

        with patch("plugins.plugins.linux_symbols_service.subprocess.Popen", return_value=mock_proc):
            with pytest.raises(RuntimeError, match="dwarf2json failed"):
                run_dwarf2json(Path("/fake/vmlinux"))

    def test_raises_on_missing_binary(self):
        """Should raise FileNotFoundError when dwarf2json is not installed."""
        with patch(
            "plugins.plugins.linux_symbols_service.subprocess.Popen",
            side_effect=FileNotFoundError,
        ):
            with pytest.raises(FileNotFoundError, match="dwarf2json not found"):
                run_dwarf2json(Path("/fake/vmlinux"))


@pytest.mark.integration
@pytest.mark.slow
class TestLinuxSymbolsIntegration:
    """Integration tests with real ddeb download and dwarf2json parsing.

    Downloads ~800MB from ddebs.ubuntu.com on first run.
    These tests verify the complete pipeline from download to parsing.

    Requires dwarf2json binary on PATH.
    """

    # Use a known good kernel version that should remain available
    KERNEL_VERSION = "6.8.0"
    BUILD = "45"
    FLAVOR = "generic"
    ARCH = "amd64"

    @pytest.fixture(scope="class")
    def vmlinux_path(self, tmp_path_factory):
        """Download ddeb once, extract vmlinux, reuse for all tests in class.

        This fixture is class-scoped to avoid re-downloading the large
        ddeb file for each test method.
        """
        url = construct_ddeb_url(self.KERNEL_VERSION, self.BUILD, self.FLAVOR, self.ARCH)

        tmp_dir = tmp_path_factory.mktemp("ddeb")
        ddeb_path = tmp_dir / "debug.ddeb"

        # Download with streaming to handle large file
        response = requests.get(url, timeout=600, stream=True)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(ddeb_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                # Progress every 50MB
                if total_size > 0 and downloaded % (50 * 1024 * 1024) < 8192:
                    percent = (downloaded / total_size) * 100
                    print(f"Downloaded {downloaded / 1024 / 1024:.0f}MB ({percent:.1f}%)")  # noqa: E231

        # Extract vmlinux from ddeb
        return extract_vmlinux_from_ddeb(ddeb_path, tmp_dir)

    @pytest.fixture(scope="class")
    def dwarf2json_data(self, vmlinux_path):
        """Run dwarf2json once, reuse parsed data across all tests in class."""
        return run_dwarf2json(vmlinux_path)

    def test_vmlinux_extracted(self, vmlinux_path):
        """Verify vmlinux was successfully extracted from ddeb."""
        assert vmlinux_path.exists()
        assert vmlinux_path.stat().st_size > 100_000_000  # vmlinux is typically >100MB

    def test_symbols_count(self, dwarf2json_data):
        """Kernel should have many symbols (typically >50k)."""
        symbols = dwarf2json_data["symbols"]
        assert len(symbols) > 50000, f"Expected >50k symbols, got {len(symbols)}"

    def test_known_kernel_symbols_exist(self, dwarf2json_data):
        """Well-known kernel symbols should be present."""
        symbols = dwarf2json_data["symbols"]

        # These symbols exist in all Linux kernels
        expected_symbols = ["schedule", "printk", "init_task", "sys_call_table"]
        found = [s for s in expected_symbols if s in symbols]

        assert len(found) >= 2, (
            f"Expected at least 2 of {expected_symbols}, "
            f"found {found} in first 20 symbols: {list(symbols.keys())[:20]}"
        )

    def test_symbol_has_address(self, dwarf2json_data):
        """Symbols should have valid addresses."""
        symbols = dwarf2json_data["symbols"]

        # Check some symbols have non-zero addresses
        non_zero = [name for name, data in list(symbols.items())[:100] if data.get("address", 0) > 0]
        assert len(non_zero) > 0, "No symbols with non-zero addresses found"

    def test_task_struct_exists(self, dwarf2json_data):
        """task_struct is the core kernel process structure - it must exist."""
        types = dwarf2json_data["user_types"]
        assert "task_struct" in types, f"task_struct not found. Types found: {list(types.keys())[:20]}"
        assert types["task_struct"]["kind"] == "struct"
        # task_struct is a large structure, typically >5KB
        assert types["task_struct"]["size"] > 1000, f"task_struct size {types['task_struct']['size']} seems too small"

    def test_task_struct_has_pid_field(self, dwarf2json_data):
        """task_struct should have a pid field."""
        types = dwarf2json_data["user_types"]
        assert "task_struct" in types
        fields = types["task_struct"]["fields"]
        assert "pid" in fields, f"pid not in task_struct fields: {list(fields.keys())[:20]}"

    def test_task_struct_has_comm_field(self, dwarf2json_data):
        """task_struct should have a comm field (process name)."""
        types = dwarf2json_data["user_types"]
        fields = types["task_struct"]["fields"]
        assert "comm" in fields, f"comm not in task_struct fields: {list(fields.keys())[:20]}"

    def test_many_struct_types_parsed(self, dwarf2json_data):
        """Kernel has many struct definitions."""
        types = dwarf2json_data["user_types"]
        # Linux kernel typically has >5000 struct types
        assert len(types) > 1000, f"Expected >1000 types, got {len(types)}"

    def test_enums_parsed(self, dwarf2json_data):
        """Should extract many enum definitions from kernel."""
        enums = dwarf2json_data["enums"]
        # Kernel has many enums
        assert len(enums) > 100, f"Expected >100 enums, got {len(enums)}"

    def test_enum_has_constants(self, dwarf2json_data):
        """Parsed enums should have constant values."""
        enums = dwarf2json_data["enums"]

        # Find an enum with constants
        enums_with_constants = [
            name for name, data in enums.items() if data.get("constants") and len(data["constants"]) > 0
        ]

        assert len(enums_with_constants) > 0, "No enums with constants found"

        # Check structure of first enum with constants
        first_enum = enums_with_constants[0]
        assert "size" in enums[first_enum]
        assert "constants" in enums[first_enum]
        assert isinstance(enums[first_enum]["constants"], dict)


@pytest.mark.integration
@pytest.mark.slow
class TestLinuxSymbolsPluckyIntegration:
    """Integration tests for Ubuntu 25.04 (plucky) kernel debug packages.

    This test validates the real network path that failed in production:
    - Resolve ddeb URL from ddebs Packages indexes
    - Download the real ddeb file
    - Extract vmlinux from archive
    """

    CODENAME = "plucky"
    KERNEL_VERSION = "6.14.0"
    BUILD = "37"
    FLAVOR = "generic"
    ARCH = "amd64"

    @pytest.fixture(scope="class")
    def plucky_ddeb_url(self):
        """Resolve ddeb URL using real ddebs package indexes."""
        url = resolve_ddeb_url_from_packages(
            self.KERNEL_VERSION,
            self.BUILD,
            self.FLAVOR,
            self.ARCH,
            self.CODENAME,
            timeout=60,
        )
        assert url is not None, "Could not resolve plucky ddeb URL from ddebs indexes"
        return url

    @pytest.fixture(scope="class")
    def plucky_vmlinux_path(self, tmp_path_factory, plucky_ddeb_url):
        """Download plucky ddeb and extract vmlinux."""
        tmp_dir = tmp_path_factory.mktemp("plucky_ddeb")
        ddeb_path = tmp_dir / "debug.ddeb"

        response = requests.get(plucky_ddeb_url, timeout=900, stream=True)
        response.raise_for_status()

        with open(ddeb_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        assert ddeb_path.exists()
        assert ddeb_path.stat().st_size > 100_000_000, "Downloaded ddeb seems too small"

        return extract_vmlinux_from_ddeb(ddeb_path, tmp_dir)

    def test_plucky_url_is_not_heuristic(self, plucky_ddeb_url):
        """Resolved URL should include package revision from index (not guessed)."""
        assert "ddebs.ubuntu.com" in plucky_ddeb_url
        assert "linux-image-unsigned-6.14.0-37-generic-dbgsym" in plucky_ddeb_url
        assert plucky_ddeb_url.endswith("_amd64.ddeb")

    def test_plucky_vmlinux_extracted(self, plucky_vmlinux_path):
        """vmlinux should be extracted successfully from the downloaded ddeb."""
        assert plucky_vmlinux_path.exists()
        assert plucky_vmlinux_path.stat().st_size > 100_000_000

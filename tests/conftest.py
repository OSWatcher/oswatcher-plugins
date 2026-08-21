"""pytest configuration for oswatcher-plugins.

Imports neogit's test fixtures to reuse Neo4j, MinIO, and object storage setup.
Also imports custom filesystem fixtures for integration testing.
"""

# Import neogit's test fixtures from neogit.testing module
# This works whether neogit is installed from git, PyPI, or local path
from neogit.testing.fixtures import *  # noqa: F401, F403

# Import oswatcher-plugins custom fixtures
from tests.fixtures_linux_fs import *  # noqa: F401, F403

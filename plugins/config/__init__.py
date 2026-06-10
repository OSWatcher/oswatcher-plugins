# Copyright 2021-2026 Mathieu Tarral
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from dynaconf import Dynaconf

APPNAME = "GPlugins"
CUR_DIR = Path(__file__).parent
LOG_FMT = "%(asctime)s:%(name)s:%(levelname)s:%(message)s"

settings = Dynaconf(
    envvar_prefix=APPNAME,
    environments=True,
    load_dotenv=True,
    # use absolute paths to import the conf from parent modules
    # from neogit.config import settings
    settings_files=[
        str(CUR_DIR / "default_settings.toml"),
    ],
)

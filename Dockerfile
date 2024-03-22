# https://github.com/orgs/python-poetry/discussions/1879#discussioncomment-7284113
# https://nanmu.me/en/posts/2023/quick-dockerfile-for-python-poetry-projects/
ARG POETRY_VERSION
FROM python:3.12-bullseye as python-base



# python
ENV PYTHONUNBUFFERED=1 \
    # prevents python creating .pyc files
    PYTHONDONTWRITEBYTECODE=1 \
    \
    # pip
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    \
    # poetry
    # https://python-poetry.org/docs/configuration/#using-environment-variables
    POETRY_VERSION=${POETRY_VERSION} \
    # make poetry install to this location
    POETRY_HOME="/opt/poetry" \
    # make poetry create the virtual environment in the project's root
    # it gets named `.venv`
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    # never create virtual environment automaticly, only use env prepared by us
    POETRY_VIRTUALENVS_CREATE=false \
    # this is where our requirements + virtual environment will live
    VIRTUAL_ENV="/venv"



# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$VIRTUAL_ENV/bin:$PATH"

# prepare virtual env
RUN python -m venv $VIRTUAL_ENV

################################
# BUILDER-BASE
# Used to build deps + create our virtual environment
################################
FROM python-base as builder-base

# install poetry - respects $POETRY_VERSION & $POETRY_HOME
# The --mount will mount the buildx cache directory to where
# Poetry and Pip store their cache so that they can re-use it
RUN --mount=type=cache,target=/root/.cache \
    curl -sSL https://install.python-poetry.org | python -

WORKDIR /app

COPY pyproject.toml poetry.lock ./
# install runtime deps to $VIRTUAL_ENV
RUN --mount=type=cache,target=/root/.cache \
    poetry install --no-root
# copy rest of allowed (non .dockerignored) files
COPY . .
# install package
RUN --mount=type=cache,target=/root/.cache \
    poetry install

# ################################
# # DEVELOPMENT
# # Image used during development / testing
# ################################
# FROM builder-base as development

# # quicker install as runtime deps are already installed
# # RUN --mount=type=cache,target=/root/.cache \
# #     poetry install --no-root --with test,lint

# CMD ["bash"]

# ################################
# # PRODUCTION
# # Final image used for runtime
# ################################
# FROM python-base as production

# # copy our venv
# COPY --from=builder-base $VIRTUAL_ENV $VIRTUAL_ENV

ENTRYPOINT [ "runner" ]

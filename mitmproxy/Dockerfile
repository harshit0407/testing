FROM docker.io/python:3.11-alpine@sha256:8d8c6d3808243160605925c2a7ab2dc5c72d0e75651699b0639143613e0855b8 AS builder
ENV PYTHONUNBUFFERED=1

RUN --mount=type=cache,target=/var/cache/apk \
    apk update && apk add --upgrade \
        ca-certificates \
        nodejs \
        build-base \
        libffi-dev \
        openssl-dev \
        unzip

COPY --from=ghcr.io/astral-sh/uv:0.8.11@sha256:8101ad825250a114e7bef89eefaa73c31e34e10ffbe5aff01562740bac97553c /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /flexget
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=scripts/bundle_webui.py,target=scripts/bundle_webui.py \
    uv run scripts/bundle_webui.py
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --group=all --no-install-project
ADD . /flexget
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --group=all

FROM docker.io/python:3.11-alpine@sha256:8d8c6d3808243160605925c2a7ab2dc5c72d0e75651699b0639143613e0855b8
ENV PYTHONUNBUFFERED=1

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --upgrade \
        ca-certificates \
        nodejs \
        tzdata \
        bash

# Copy the application from the builder
COPY --from=builder --chown=app:app /flexget /flexget

# Copy the test script
COPY test.sh /test.sh
RUN chmod +x /test.sh

# Place executables in the environment at the front of the path
ENV PATH="/flexget/.venv/bin:$PATH"

# Set working directory to flexget for running tests
WORKDIR /flexget

# Run the test script instead of FlexGet
ENTRYPOINT ["/test.sh"]

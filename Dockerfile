# syntax=docker/dockerfile:1
FROM python:3.14-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy workspace files for dependency resolution. README.md and LICENSE are
# build inputs, not documentation: `readme` and `license-files` in the package
# metadata name them, and hatchling fails the build outright if either is
# missing.
COPY pyproject.toml uv.lock ./
COPY fastsmtp/pyproject.toml fastsmtp/README.md fastsmtp/LICENSE fastsmtp/
COPY fastsmtp/src fastsmtp/src
COPY fastsmtp-cli/pyproject.toml fastsmtp-cli/README.md fastsmtp-cli/LICENSE fastsmtp-cli/
COPY fastsmtp-cli/src fastsmtp-cli/src

# Install both workspace packages and their dependencies. The CLI's deps
# (typer, httpx, rich) are already pulled in for the server, so this is close
# to free in layer size - see issue #142.
RUN uv sync --frozen --no-dev --package fastsmtp --package fastsmtp-cli

FROM python:3.14-slim AS runtime

# Create non-root user
RUN useradd -m -u 1000 fastsmtp

WORKDIR /app

# Copy virtual environment and both packages' source from builder. This is a
# server image that also carries the CLI (`fsmtp`) so an operator with only
# the container still has a supported path to the API - see issue #142.
COPY --from=builder --chown=fastsmtp:fastsmtp /app/.venv /app/.venv
# The migrations ship inside the package (src/fastsmtp/alembic), so the src
# tree is the whole of what has to be copied for `fastsmtp db upgrade` to work.
COPY --from=builder --chown=fastsmtp:fastsmtp /app/fastsmtp/src /app/fastsmtp/src
COPY --from=builder --chown=fastsmtp:fastsmtp /app/fastsmtp-cli/src /app/fastsmtp-cli/src

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER fastsmtp

# Default command
CMD ["fastsmtp", "serve"]

# Expose ports
EXPOSE 8000 2525 4650

# Health check using Python (curl not available in slim image)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

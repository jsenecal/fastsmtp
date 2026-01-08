# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy workspace files for dependency resolution
COPY pyproject.toml uv.lock ./
COPY fastsmtp/pyproject.toml fastsmtp/
COPY fastsmtp/src fastsmtp/src
COPY fastsmtp/alembic fastsmtp/alembic
COPY fastsmtp/alembic.ini fastsmtp/
# Need empty fastsmtp-cli for workspace resolution
RUN mkdir -p fastsmtp-cli/src/fastsmtp_cli && \
    echo '"""Stub for Docker build."""' > fastsmtp-cli/src/fastsmtp_cli/__init__.py
COPY fastsmtp-cli/pyproject.toml fastsmtp-cli/

# Install fastsmtp package and dependencies
RUN uv sync --frozen --no-dev --package fastsmtp

FROM python:3.12-slim AS runtime

# Create non-root user
RUN useradd -m -u 1000 fastsmtp

WORKDIR /app

# Copy virtual environment and fastsmtp package from builder
COPY --from=builder --chown=fastsmtp:fastsmtp /app/.venv /app/.venv
COPY --from=builder --chown=fastsmtp:fastsmtp /app/fastsmtp/src /app/fastsmtp/src
COPY --from=builder --chown=fastsmtp:fastsmtp /app/fastsmtp/alembic /app/fastsmtp/alembic
COPY --from=builder --chown=fastsmtp:fastsmtp /app/fastsmtp/alembic.ini /app/fastsmtp/alembic.ini

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

# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy workspace files
COPY pyproject.toml uv.lock ./
COPY fastsmtp/pyproject.toml fastsmtp/
COPY fastsmtp/src fastsmtp/src
COPY fastsmtp/alembic fastsmtp/alembic
COPY fastsmtp/alembic.ini fastsmtp/

# Install dependencies
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime

# Create non-root user
RUN useradd -m -u 1000 fastsmtp

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/fastsmtp /app/fastsmtp

# Set environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER fastsmtp

# Default command
CMD ["python", "-m", "fastsmtp.cli", "serve"]

# Expose ports
EXPOSE 8000 25 465

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Getting Started

## Prerequisites

- Python 3.12+
- PostgreSQL 16+ (or MariaDB 10.6+)
- uv (recommended) or pip

## Installation

```bash
# Clone the repository
git clone https://github.com/jsenecal/fastsmtp.git
cd fastsmtp

# Install dependencies
uv sync

# Set up environment
export FASTSMTP_DATABASE_URL="postgresql+asyncpg://user:pass@localhost/fastsmtp"
export FASTSMTP_ROOT_API_KEY="your-secure-root-key"

# Run database migrations (needs only FASTSMTP_DATABASE_URL)
uv run fastsmtp db upgrade head

# Start the server (needs FASTSMTP_ROOT_API_KEY as well)
uv run fastsmtp serve
```

## Docker

```bash
# Pull the image
docker pull ghcr.io/jsenecal/fastsmtp:latest

# Run with required environment variables
docker run -d \
  -p 8000:8000 -p 2525:2525 -p 4650:4650 \
  -e FASTSMTP_DATABASE_URL="postgresql+asyncpg://user:pass@host/fastsmtp" \
  -e FASTSMTP_ROOT_API_KEY="your-secure-key" \
  ghcr.io/jsenecal/fastsmtp:latest
```

## Docker Compose

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fastsmtp
      POSTGRES_USER: fastsmtp
      POSTGRES_PASSWORD: fastsmtp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fastsmtp"]
      interval: 5s
      timeout: 5s
      retries: 5

  fastsmtp:
    image: ghcr.io/jsenecal/fastsmtp:latest
    ports:
      - "8000:8000"   # API
      - "2525:2525"   # SMTP
      - "4650:4650"   # SMTP TLS
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_API_HOST: 0.0.0.0
      FASTSMTP_SMTP_HOST: 0.0.0.0
    depends_on:
      postgres:
        condition: service_healthy

  worker:
    image: ghcr.io/jsenecal/fastsmtp:latest
    command: ["fastsmtp", "serve", "--worker-only"]
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
    depends_on:
      postgres:
        condition: service_healthy
    deploy:
      replicas: 2

volumes:
  postgres_data:
```

## Docker Compose with S3 (MinIO)

For attachment storage with MinIO:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fastsmtp
      POSTGRES_USER: fastsmtp
      POSTGRES_PASSWORD: fastsmtp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fastsmtp"]
      interval: 5s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  createbucket:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myminio http://minio:9000 minioadmin minioadmin;
      mc mb --ignore-existing myminio/attachments;
      exit 0;
      "

  fastsmtp:
    image: ghcr.io/jsenecal/fastsmtp:latest
    ports:
      - "8000:8000"
      - "2525:2525"
      - "4650:4650"
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_API_HOST: 0.0.0.0
      FASTSMTP_SMTP_HOST: 0.0.0.0
      FASTSMTP_ATTACHMENT_STORAGE: s3
      FASTSMTP_S3_ENDPOINT_URL: http://minio:9000
      FASTSMTP_S3_BUCKET: attachments
      FASTSMTP_S3_ACCESS_KEY: minioadmin
      FASTSMTP_S3_SECRET_KEY: minioadmin
      FASTSMTP_S3_PRESIGNED_URLS: "true"
    depends_on:
      postgres:
        condition: service_healthy
      createbucket:
        condition: service_completed_successfully

  worker:
    image: ghcr.io/jsenecal/fastsmtp:latest
    command: ["fastsmtp", "serve", "--worker-only"]
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_ATTACHMENT_STORAGE: s3
      FASTSMTP_S3_ENDPOINT_URL: http://minio:9000
      FASTSMTP_S3_BUCKET: attachments
      FASTSMTP_S3_ACCESS_KEY: minioadmin
      FASTSMTP_S3_SECRET_KEY: minioadmin
    depends_on:
      postgres:
        condition: service_healthy
    deploy:
      replicas: 2

volumes:
  postgres_data:
  minio_data:
```

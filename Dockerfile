# Production Dockerfile for Aegis Gateway & Console UI
FROM python:3.13-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AEGIS_LOG_PATH=/app/aegis-log.jsonl

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy repository code
COPY aegis /app/aegis
COPY pyproject.toml /app/

# Expose default HTTP port
EXPOSE 8000

# Healthcheck endpoint
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run uvicorn server serving Aegis API and Console UI
CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8000"]

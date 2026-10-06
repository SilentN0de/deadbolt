# Deadbolt — one-container image.
# Python 3.13 slim, non-root user, SQLite data persisted via /app/data.
FROM python:3.13-slim

WORKDIR /app

# Install dependencies first (better layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY . .

# Run as a non-root user; ensure the data dir is writable.
RUN useradd --create-home --shell /usr/sbin/nologin deadbolt \
    && mkdir -p /app/data \
    && chown -R deadbolt:deadbolt /app
USER deadbolt

# Inside the container we must listen on all interfaces; docker compose
# publishes the port on the host's loopback only (127.0.0.1:8000),
# preserving Deadbolt's localhost-only posture.
ENV DEADBOLT_HOST=0.0.0.0 \
    DEADBOLT_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
VOLUME ["/app/data"]

CMD ["sh", "-c", "python -m uvicorn api.main:app --host \"${DEADBOLT_HOST}\" --port \"${DEADBOLT_PORT}\""]

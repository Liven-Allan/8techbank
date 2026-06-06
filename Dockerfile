# Stage 1 – dependency installation (throwaway layer)
FROM python:3.11-slim AS builder

WORKDIR /build

# Install Python dependencies into an isolated prefix so we can copy them
# cleanly into the final image without pip or wheel tooling.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2 – lean production image
FROM python:3.11-slim AS production

# Create a non-root user and group.
# UID/GID 1001 avoids collision with typical system accounts.
RUN groupadd --gid 1001 appgroup \
 && useradd --uid 1001 --gid appgroup \
             --no-create-home --shell /usr/sbin/nologin \
             appuser

# Copy pre-installed Python packages from the builder stage.
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source code.
COPY --chown=appuser:appgroup . .

# Create the data directory; the volume will be mounted here at runtime.
# We still create it so ownership is correct even without a bind-mount.
RUN mkdir -p /app/data \
 && chown appuser:appgroup /app/data

# Switch to the unprivileged user for all subsequent layers and the runtime.
USER appuser

# Runtime configuration

# Disable the Flask development server's debug mode and reloader.
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0

# Secrets MUST be supplied at runtime via environment variables or Docker
# secrets. The defaults below are intentionally invalid so the application
# fails loudly rather than running with a known-weak key.
ENV SECRET_KEY=REPLACE_ME_AT_RUNTIME
ENV JWT_SECRET=REPLACE_ME_AT_RUNTIME

# SQLite database lives on the writable volume mounted at /app/data.
ENV DATABASE_PATH=/app/data/8techbank.db

# The application listens on an unprivileged port – no CAP_NET_BIND_SERVICE
# needed.
EXPOSE 5000

# Filesystem note

# The root filesystem is mounted read-only by docker-compose (read_only: true).
# Two tmpfs mounts are injected:
#   /tmp          – ephemeral scratch space for Flask/Werkzeug
#   /app/data     – writable volume for the SQLite database
# Everything else under /app is immutable after the image build.

ENTRYPOINT ["python", "app.py"]
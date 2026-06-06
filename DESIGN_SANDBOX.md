# 8TechBank – Application Sandboxing Design Document

## Overview

The current 8TechBank deployment runs as root inside a single container with debug mode enabled and hardcoded secrets. This document describes a production sandboxing strategy across five areas.

## (a) Containerisation with a Least-Privilege User

The Dockerfile uses a two-stage build. The first stage installs Python dependencies; the second copies only the installed packages and application source into a clean `python:3.11-slim` image, leaving no build tooling behind. A dedicated system account (`appuser`, UID 1001) is created with no login shell and no home directory. The `USER appuser` directive ensures the Flask process never holds root inside the container. In docker-compose, `security_opt: [no-new-privileges:true]` and `cap_drop: [ALL]` prevent any setuid binary from escalating privileges. `FLASK_DEBUG` is set to `0` and `FLASK_ENV` to `production`, disabling the Werkzeug interactive debugger that the original code exposes. Secrets (`SECRET_KEY`, `JWT_SECRET`) are injected at runtime via Docker secrets mounted at `/run/secrets/`, never hardcoded in the image or Compose file.

## (b) Network Segmentation

Two isolated Docker bridge networks separate the three tiers:

- **`frontend_net`** — carries HTTP between nginx and the Flask app.
- **`appdb_net`** — private link between the app and the database, declared `internal: true` so it has no external routing.

nginx is the only container with a host port binding (80/443). The Flask app is reachable only from nginx via `frontend_net`. The database sits exclusively on `appdb_net` and has no presence on `frontend_net`, making it unreachable from the public internet even if nginx is compromised.

## (c) Filesystem Restrictions

`read_only: true` is applied to every container, mounting the root filesystem immutable. Legitimate writable locations are granted via two tmpfs mounts:

- `/tmp` — in-memory, `noexec,nosuid`, for Flask/Werkzeug scratch space.
- `/app/data` — a named Docker volume for the SQLite database, the only path the application must write persistently.

All Python source, templates, and static files are baked into the image at build time and cannot be modified at runtime. This blocks an attacker who achieves code execution from persisting backdoors or altering application logic.

## (d) Resource Limits

The following limits are applied per service to prevent a compromised container from exhausting host resources:

| Resource | nginx | app | db |
|---|---|---|---|
| CPU limit | 0.5 core | 1.0 core | 0.5 core |
| Memory limit | 128 MB | 256 MB | 256 MB |
| Max processes | 50 | 50 | 50 |
| Max open files | 1 024 | 1 024 | 1 024 |

`pids_limit: 50` defeats fork-bomb attacks. The hard memory limit causes the kernel to OOM-kill only the offending container, leaving the host and sibling services unaffected.

## (e) Implementation

See the accompanying `Dockerfile` and `docker-compose.yml` for the full implementation of the above design.

The Dockerfile creates `appuser`, installs dependencies in a builder stage, copies only the application into the final image, and sets `USER appuser` before the entrypoint. The Compose file wires up nginx, app, and db across the two networks described above, applies `read_only: true` with `/tmp` and `/app/data` tmpfs mounts, drops all Linux capabilities, enforces CPU and memory limits via `deploy.resources`, and restricts process counts with `pids_limit`. Together these controls enforce least privilege at the user, network, filesystem, and resource layers.
"""
routes/api.py — 8TechBank Secure REST API Layer
================================================
Implements:
  4.1  JWT-based authentication & authorisation
  4.2  Rate limiting & Marshmallow input validation
"""

# ──────────────────────────────────────────────
# Standard-library / third-party imports
# ──────────────────────────────────────────────
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request
from marshmallow import Schema, ValidationError, fields, validate
from marshmallow.validate import Length, Range

from database import get_db
from extensions import limiter  # Flask-Limiter singleton (key_func=get_remote_address)
from werkzeug.security import check_password_hash

# ══════════════════════════════════════════════
# Blueprint registration
# ══════════════════════════════════════════════
api_bp = Blueprint("api", __name__)


# ══════════════════════════════════════════════
# § 4.1  JWT Authentication & Authorisation
# ══════════════════════════════════════════════

# ── Database helpers ──────────────────────────

def _get_user_by_username(username: str):
    """
    Fetch a user row by username using a *parameterised* query.

    Security: parameterised queries (the `?` placeholder) prevent SQL
    injection by passing the value out-of-band from the SQL text.
    """
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),  # <── value passed as parameter, never string-concatenated
    )
    row = cur.fetchone()
    conn.close()
    return row


def _get_user_by_id(user_id: int):
    """Return non-sensitive columns only — never expose the password field."""
    conn = get_db()
    cur = conn.execute(
        "SELECT id, username, email, display_name, "
        "       account_number, balance, role, created_at "
        "FROM   users WHERE id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()
    return row


# ── Token generation ─────────────────────────

def _generate_tokens(user) -> tuple[str, str]:
    """
    Create an access token and a refresh token for the authenticated user.

    Access token (15 min, configurable via JWT_ACCESS_EXPIRES):
      • Short lifetime limits the damage window if a token is stolen.
      • Carries 'sub' (user id), 'username', 'role', 'type':'access'.

    Refresh token (7 days, configurable via JWT_REFRESH_EXPIRES):
      • Longer-lived; used *only* to obtain a new access token.
      • Does NOT carry role/username — fetch fresh from DB on refresh.
      • In production, store a hash of the refresh token in a DB revocation
        table so it can be invalidated on logout or compromise.

    Both tokens are HMAC-SHA-256 signed (HS256) using the JWT_SECRET value
    from app config.  Keep JWT_SECRET long, random and out of source control
    (environment variable or secrets manager).
    """
    now = datetime.now(timezone.utc)

    # ── Access token payload ──────────────────
    access_payload = {
        "sub": user["id"],          # subject — unique user identifier
        "username": user["username"],
        "role": user["role"],       # used by requires_role() RBAC decorator
        "type": "access",           # token-type claim prevents refresh→access confusion
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=current_app.config["JWT_ACCESS_EXPIRES"])) .timestamp()),
    }

    # ── Refresh token payload ─────────────────
    refresh_payload = {
        "sub": user["id"],
        "type": "refresh",          # explicitly mark as refresh-only
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=current_app.config["JWT_REFRESH_EXPIRES"])) .timestamp()),
    }

    # jwt.encode() returns str in PyJWT ≥ 2.x
    access_token = jwt.encode(
        access_payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    refresh_token = jwt.encode(
        refresh_payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    return access_token, refresh_token


# ── Token decoding ────────────────────────────

def _decode_token(token: str, expected_type: str = "access"):
    """
    Verify and decode a JWT, returning (payload, None) on success or
    (None, (message, http_status)) on failure.

    PyJWT automatically validates:
      • Signature integrity (tampering)
      • Expiry (`exp` claim)   — raises ExpiredSignatureError
      • Not-before (`nbf`)     — raises ImmatureSignatureError
    We additionally validate the `type` claim to prevent a refresh token
    from being accepted as an access token and vice-versa.
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
        )
    except jwt.ExpiredSignatureError:
        return None, ("Token has expired", 401)
    except jwt.InvalidTokenError:
        # Covers: bad signature, wrong algorithm, malformed header, etc.
        return None, ("Invalid token", 401)

    if payload.get("type") != expected_type:
        # E.g. someone submits a refresh token to a resource endpoint
        return None, (f"Wrong token type: expected '{expected_type}'", 401)

    return payload, None


# ── JWT middleware ────────────────────────────

def jwt_required(f):
    """
    Decorator that enforces JWT authentication on a route.

    Expected request header:
        Authorization: Bearer <access_token>

    On success, populates flask.g.current_user with:
        {'id': int, 'username': str, 'role': str}

    Security notes:
      • Only the 'Bearer' scheme is accepted; other schemes are rejected.
      • Token claims come from the *verified* payload, not from the request
        body, so they cannot be forged without the JWT_SECRET.
      • g.current_user is request-scoped and never persisted.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        # Require "Authorization: Bearer <token>"
        if not auth_header or not auth_header.lower().startswith("bearer "):
            return (
                jsonify({"error": "Authorization header missing or malformed. "
                                  "Use: Authorization: Bearer <token>"}),
                401,
            )

        token = auth_header.split(None, 1)[1].strip()
        payload, err = _decode_token(token, expected_type="access")

        if err:
            return jsonify({"error": err[0]}), err[1]

        # Attach minimal, safe claims to the request context
        g.current_user = {
            "id":       payload["sub"],
            "username": payload["username"],
            "role":     payload["role"],
        }
        return f(*args, **kwargs)

    return decorated


# ── Role-based access control ─────────────────

def requires_role(role: str):
    """
    Decorator that restricts a route to users with a specific role.

    Must be applied *after* @jwt_required so that g.current_user exists:

        @api_bp.route('/api/admin/...')
        @jwt_required          ← runs first (outer wrapper)
        @requires_role('admin')
        def my_view(): ...

    Roles in use:
      'user'  — standard account holder
      'admin' — privileged staff account; can access /api/admin/* endpoints

    Security note: the role value is taken from the *signed* JWT payload, so
    it cannot be altered client-side without invalidating the signature.
    """
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not getattr(g, "current_user", None):
                # Should never reach here if @jwt_required is applied first,
                # but included as a defensive check.
                return jsonify({"error": "Authentication required"}), 401

            if g.current_user.get("role") != role:
                # 403 Forbidden — authenticated but not authorised
                return jsonify({"error": f"Forbidden — requires role '{role}'"}), 403

            return f(*args, **kwargs)
        return decorated
    return wrapper


# ══════════════════════════════════════════════
# § 4.2  Marshmallow Input Validation Schemas
# ══════════════════════════════════════════════

class AuthSchema(Schema):
    """
    Validates POST /api/auth/token request body.

    Constraints:
      • Both fields are required (missing → 422).
      • Max 150 chars prevents oversized-input DoS on the DB layer.
      • unknown=EXCLUDE: extra fields (e.g. injected 'role') are silently
        discarded rather than raising an error.
    """
    class Meta:
        unknown = __import__('marshmallow').EXCLUDE  # ignore extra fields

    username = fields.Str(
        required=True,
        validate=Length(min=1, max=150),
        error_messages={"required": "username is required"},
    )
    password = fields.Str(
        required=True,
        validate=Length(min=1, max=150),
        error_messages={"required": "password is required"},
    )


class RefreshSchema(Schema):
    """Validates POST /api/auth/refresh request body."""
    class Meta:
        unknown = __import__('marshmallow').EXCLUDE

    refresh_token = fields.Str(
        required=True,
        validate=Length(min=10),  # sane minimum — real JWTs are much longer
    )


class TransferSchema(Schema):
    """
    Validates POST /api/transfer request body.

    Constraints:
      • amount must be a positive number ≤ 1,000,000 (prevents integer
        overflow / absurd values reaching the DB).
      • memo is optional but capped at 200 chars to prevent oversized input.
      • to_account must be present and non-empty.
    """
    to_account = fields.Str(required=True, validate=Length(min=1, max=50))
    amount = fields.Float(
        required=True,
        validate=Range(min=0.01, max=1_000_000.0),
    )
    memo = fields.Str(
        load_default="",
        validate=Length(max=200),
    )


# ══════════════════════════════════════════════
# § 4.1 (a) — Token Issuance Endpoint
# ══════════════════════════════════════════════

@api_bp.route("/api/auth/token", methods=["POST"])
@limiter.limit(
    # § 4.2 (a) — Brute-force protection: max 5 attempts per minute per IP
    "5 per minute",
    # Custom error message returned as JSON on 429
    error_message="Too many login attempts. Please wait 60 seconds.",
)
def api_auth_token():
    """
    POST /api/auth/token
    Issue an access + refresh token pair on valid credentials.

    Request body (application/json):
        { "username": "alice", "password": "s3cret" }

    Responses:
        200  { "access_token": "...", "refresh_token": "..." }
        400  Invalid / non-JSON body
        401  Credentials incorrect
        422  Schema validation error (field missing or too long)
        429  Rate limit exceeded (5 attempts / minute / IP)

    Security notes:
      - Rate limiter (5/min/IP) prevents brute-force credential stuffing.
      - Input validation rejects oversized payloads before they touch the DB.
      - Parameterised DB query prevents SQL injection.
      - Identical 401 response for "unknown user" and "wrong password" prevents
        username enumeration.
      - Plaintext password comparison is intentional in this demo; production
        MUST use bcrypt / argon2 with constant-time comparison (e.g. werkzeug
        check_password_hash).
    """
    # ── Parse body ────────────────────────────
    # Use `is None` check (not `not data`) so that an empty JSON object {}
    # reaches the schema validator and returns 422 rather than 400.
    data = request.get_json(silent=True)
    if data is None:
        # Non-JSON content-type, empty body, or unparseable JSON
        return jsonify({"error": "Request body must be valid JSON"}), 400

    # ── Validate schema ───────────────────────
    try:
        validated = AuthSchema().load(data)
    except ValidationError as exc:
        # 422 Unprocessable Entity — body is JSON but fails field constraints
        return jsonify({"error": "Validation failed", "details": exc.messages}), 422

    username = validated["username"]
    password = validated["password"]

    # ── Authenticate ──────────────────────────
    user = _get_user_by_username(username)

    if not user:
        # Do NOT reveal "user does not exist" — generic message only
        return jsonify({"error": "Invalid credentials"}), 401

    # Verify hashed password
    if not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # ── Issue tokens ──────────────────────────
    access_token, refresh_token = _generate_tokens(user)

    return jsonify({
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "bearer",
        "expires_in":    current_app.config["JWT_ACCESS_EXPIRES"],  # seconds
    }), 200


# ══════════════════════════════════════════════
# § 4.1 (d) — Refresh Endpoint
# ══════════════════════════════════════════════

@api_bp.route("/api/auth/refresh", methods=["POST"])
def api_auth_refresh():
    """
    POST /api/auth/refresh
    Exchange a valid refresh token for a new access token.

    Request body (application/json):
        { "refresh_token": "..." }

    Responses:
        200  { "access_token": "...", "expires_in": 900 }
        400  Non-JSON body
        401  Expired or invalid refresh token
        404  User no longer exists
        422  Schema validation error

    Security notes:
      - Only tokens with type='refresh' are accepted (validated in _decode_token).
      - A new access token is issued; the refresh token is NOT rotated in this
        implementation. Production systems should rotate refresh tokens and
        maintain a server-side revocation list to support logout.
      - Fresh user data (including current role) is re-read from the DB so that
        role changes take effect on the next refresh without requiring full
        re-login.
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        validated = RefreshSchema().load(data)
    except ValidationError as exc:
        return jsonify({"error": "Validation failed", "details": exc.messages}), 422

    payload, err = _decode_token(validated["refresh_token"], expected_type="refresh")
    if err:
        return jsonify({"error": err[0]}), err[1]

    user = _get_user_by_id(payload["sub"])
    if not user:
        return jsonify({"error": "User account not found"}), 404

    # Issue a new access token with fresh claims (use timezone-aware UTC)
    now = datetime.now(timezone.utc)
    access_payload = {
        "sub":      user["id"],
        "username": user["username"],
        "role":     user["role"],   # re-read from DB — picks up any role changes
        "type":     "access",
        "iat":      int(now.timestamp()),
        "exp":      int(
            (now + timedelta(seconds=current_app.config["JWT_ACCESS_EXPIRES"]))
            .timestamp()
        ),
    }
    access_token = jwt.encode(
        access_payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )

    return jsonify({
        "access_token": access_token,
        "token_type":   "bearer",
        "expires_in":   current_app.config["JWT_ACCESS_EXPIRES"],
    }), 200


# ══════════════════════════════════════════════
# Protected resource endpoints
# ══════════════════════════════════════════════

@api_bp.route("/api/user/profile")
@jwt_required
def api_user_profile():
    """
    GET /api/user/profile          [requires: valid access token]
    Return non-sensitive profile fields for the caller.

    The password field is never returned.
    """
    user = _get_user_by_id(g.current_user["id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id":             user["id"],
        "username":       user["username"],
        "email":          user["email"],
        "display_name":   user["display_name"],
        "account_number": user["account_number"],
        "balance":        user["balance"],
        "role":           user["role"],
        "created_at":     user["created_at"],
    }), 200


@api_bp.route("/api/admin/stats")
@jwt_required
@requires_role("admin")  # § 4.1 (c) — admin-only RBAC gate
def api_admin_stats():
    """
    GET /api/admin/stats           [requires: valid access token + role='admin']
    Return aggregate platform statistics.

    Security: @jwt_required validates the token; @requires_role('admin')
    checks the role claim.  A regular 'user' token receives 403 Forbidden.
    """
    conn = get_db()
    stats = {
        "total_users":        conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_transactions": conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
        "total_volume":       conn.execute("SELECT COALESCE(SUM(amount),0) FROM transactions").fetchone()[0],
    }
    conn.close()
    return jsonify({"status": "ok", "data": stats}), 200


@api_bp.route("/api/transfer", methods=["POST"])
@jwt_required
def api_transfer():
    """
    POST /api/transfer             [requires: valid access token]
    Initiate a fund transfer to another account.

    Request body (application/json):
        { "to_account": "8TB-123456", "amount": 250.00, "memo": "Lunch" }

    Demonstrates per-endpoint input validation via TransferSchema.
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    try:
        validated = TransferSchema().load(data)
    except ValidationError as exc:
        return jsonify({"error": "Validation failed", "details": exc.messages}), 422

    # Business-logic stub — full transfer logic lives in routes/transfer.py
    return jsonify({
        "status":     "accepted",
        "to_account": validated["to_account"],
        "amount":     validated["amount"],
        "memo":       validated["memo"],
        "message":    "Transfer queued (stub — full logic in routes/transfer.py)",
    }), 202

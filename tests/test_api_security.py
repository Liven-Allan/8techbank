"""
tests/test_api_security.py — 8TechBank API Security Test Suite
===============================================================
Covers requirements 4.1 and 4.2:

  4.1  JWT authentication, token expiry, refresh, role-based access control
  4.2  Rate limiting (5/min/IP), Marshmallow schema validation,
       oversized / malformed input rejection

Run with:
    cd 8techbank
    pytest tests/test_api_security.py -v

Implementation note on rate-limit isolation
-------------------------------------------
Flask-Limiter's default key function is get_remote_address(), which always
returns 127.0.0.1 inside the Flask test client regardless of headers.
Therefore all requests share the same rate-limit bucket.

Strategy:
  • Tests that do NOT test the rate limiter call limiter.reset() before each
    request so the counter is never exhausted.
  • Tests that DO test the rate limiter deliberately exhaust the counter and
    skip the reset, then call reset() in teardown so later tests are unaffected.
"""

import os
import pytest
from datetime import datetime, timedelta

import jwt as pyjwt

from app import app as flask_app
from database import init_db, seed_db
import database as db_module
from extensions import limiter

# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Initialise and seed a temp database once for the whole session."""
    db_module.DATABASE_PATH = "/tmp/test_8techbank.db"
    if os.path.exists(db_module.DATABASE_PATH):
        os.remove(db_module.DATABASE_PATH)
    init_db()
    seed_db()
    yield
    if os.path.exists(db_module.DATABASE_PATH):
        os.remove(db_module.DATABASE_PATH)


@pytest.fixture
def client():
    """
    Flask test client.
    Resets the rate-limiter storage before every test so that tests
    that call /api/auth/token for setup purposes don't accidentally
    trip the 5/min/IP limit.

    The two TestRateLimiting tests deliberately do NOT call reset() inside
    themselves — they need a fresh counter, which this fixture provides.
    """
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        with flask_app.app_context():
            limiter.reset()   # clear all counters for this test
        yield c
        # Ensure the limiter is clean after each test so later tests are unaffected
        with flask_app.app_context():
            limiter.reset()


# ── Helpers ───────────────────────────────────

def _get_token(client, username="admin", password="admin123"):
    return client.post(
        "/api/auth/token",
        json={"username": username, "password": password},
    )


def _access_token(client, username="admin", password="admin123") -> str:
    r = _get_token(client, username, password)
    assert r.status_code == 200, \
        f"Expected 200 from /api/auth/token, got {r.status_code}: {r.get_data(as_text=True)}"
    return r.get_json()["access_token"]


def _refresh_token(client, username="admin", password="admin123") -> str:
    r = _get_token(client, username, password)
    assert r.status_code == 200
    return r.get_json()["refresh_token"]


# ══════════════════════════════════════════════
# § 4.1  JWT Authentication & Authorisation
# ══════════════════════════════════════════════

class TestTokenIssuance:
    """POST /api/auth/token — happy-path and credential rejection."""

    def test_valid_admin_credentials_return_200(self, client):
        """Valid admin credentials must return both token types and metadata."""
        r = _get_token(client)
        assert r.status_code == 200
        body = r.get_json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == flask_app.config["JWT_ACCESS_EXPIRES"]

    def test_valid_user_credentials_return_200(self, client):
        """Ordinary user credentials must also work."""
        r = _get_token(client, "user1", "password123")
        assert r.status_code == 200

    def test_wrong_password_returns_401(self, client):
        """Wrong password must yield 401, not a 5xx."""
        r = _get_token(client, "admin", "wrongpassword")
        assert r.status_code == 401
        assert "Invalid credentials" in r.get_json()["error"]

    def test_unknown_user_returns_401(self, client):
        """
        Unknown username must yield the same 401 response as a wrong password.
        This prevents username enumeration — an attacker cannot distinguish
        'user does not exist' from 'wrong password'.
        """
        r = _get_token(client, "nonexistent_xyz", "anything")
        assert r.status_code == 401
        assert "Invalid credentials" in r.get_json()["error"]


class TestJWTMiddleware:
    """§ 4.1 (b) — JWT validation middleware protects all /api/* routes."""

    def test_protected_route_without_token_returns_401(self, client):
        """No token → 401 Unauthorized."""
        r = client.get("/api/user/profile")
        assert r.status_code == 401

    def test_protected_route_with_garbage_token_returns_401(self, client):
        """An arbitrary string in the Bearer header → 401."""
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        assert r.status_code == 401

    def test_protected_route_with_valid_token_returns_200(self, client):
        """A legitimate access token must grant access."""
        token = _access_token(client)
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_wrong_auth_scheme_returns_401(self, client):
        """'Token <x>' (not 'Bearer <x>') must be rejected with 401."""
        token = _access_token(client)
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Token {token}"},
        )
        assert r.status_code == 401

    def test_tampered_jwt_signature_returns_401(self, client):
        """
        Modifying the last character of the JWT signature segment must trigger
        an InvalidSignatureError and return 401.
        This verifies the middleware does not skip signature verification.
        """
        token = _access_token(client)
        header, payload, sig = token.rsplit(".", 2)
        bad_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        bad_token = f"{header}.{payload}.{bad_sig}"
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {bad_token}"},
        )
        assert r.status_code == 401

    def test_expired_access_token_returns_401(self, client):
        """
        A token with exp in the past must be rejected with 401.
        Verifies that PyJWT's expiry check is active.
        """
        now = datetime.utcnow()
        expired_payload = {
            "sub": 1,
            "username": "admin",
            "role": "admin",
            "type": "access",
            "iat": int((now - timedelta(seconds=20)).timestamp()),
            "exp": int((now - timedelta(seconds=10)).timestamp()),  # already expired
        }
        expired_token = pyjwt.encode(
            expired_payload,
            flask_app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert r.status_code == 401
        assert "expired" in r.get_json()["error"].lower()

    def test_refresh_token_rejected_on_resource_endpoint(self, client):
        """
        A refresh token ('type':'refresh') must NOT be accepted by resource
        endpoints that expect 'type':'access'.
        The type-claim check in _decode_token prevents token-type confusion.
        """
        rt = _refresh_token(client)
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {rt}"},
        )
        assert r.status_code == 401
        assert "Wrong token type" in r.get_json()["error"]


class TestRBACRoles:
    """§ 4.1 (c) — Role-based access control distinguishing 'user' and 'admin'."""

    def test_admin_can_access_admin_endpoint(self, client):
        """Admin token must return 200 on /api/admin/stats."""
        token = _access_token(client, "admin", "admin123")
        r = client.get(
            "/api/admin/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_user_role_cannot_access_admin_endpoint(self, client):
        """
        A 'user' role token must receive 403 Forbidden on admin-only endpoints.
        The user is authenticated (valid JWT) but lacks the required role.
        """
        token = _access_token(client, "user1", "password123")
        r = client.get(
            "/api/admin/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403
        assert "admin" in r.get_json()["error"].lower()

    def test_unauthenticated_request_to_admin_endpoint_returns_401(self, client):
        """No token at all → 401 (not 403), since the request is unauthenticated."""
        r = client.get("/api/admin/stats")
        assert r.status_code == 401

    def test_profile_endpoint_returns_own_user_data(self, client):
        """
        The profile endpoint must return data for the token's subject (user1),
        not for a different user, and must never expose the password field.
        """
        token = _access_token(client, "user1", "password123")
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        body = r.get_json()
        assert body["username"] == "user1"
        assert "password" not in body

    def test_role_claim_comes_from_verified_signature(self, client):
        """
        An attacker cannot forge role='admin' without the JWT_SECRET.
        Build a token with a forged role and a bad signature — must return 401.
        """
        forged_payload = {
            "sub": 99,
            "username": "hacker",
            "role": "admin",       # forged
            "type": "access",
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        }
        forged_token = pyjwt.encode(
            forged_payload,
            "wrong_secret",        # signed with the wrong key
            algorithm="HS256",
        )
        r = client.get(
            "/api/admin/stats",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        assert r.status_code == 401


class TestTokenRefresh:
    """§ 4.1 (d) — Token expiry and refresh mechanism."""

    def test_valid_refresh_token_issues_new_access_token(self, client):
        """POST /api/auth/refresh with a valid refresh token must return a new access token."""
        rt = _refresh_token(client)
        r = client.post("/api/auth/refresh", json={"refresh_token": rt})
        assert r.status_code == 200
        body = r.get_json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["expires_in"] == flask_app.config["JWT_ACCESS_EXPIRES"]

    def test_new_access_token_is_functional(self, client):
        """The access token obtained via refresh must work on protected routes."""
        rt = _refresh_token(client)
        r = client.post("/api/auth/refresh", json={"refresh_token": rt})
        new_at = r.get_json()["access_token"]

        profile = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {new_at}"},
        )
        assert profile.status_code == 200

    def test_access_token_rejected_on_refresh_endpoint(self, client):
        """
        An access token must NOT be accepted by /api/auth/refresh.
        The type='refresh' check prevents token-type confusion / privilege escalation.
        """
        at = _access_token(client)
        r = client.post("/api/auth/refresh", json={"refresh_token": at})
        assert r.status_code == 401
        assert "Wrong token type" in r.get_json()["error"]

    def test_expired_refresh_token_is_rejected(self, client):
        """A refresh token with exp in the past must be rejected with 401."""
        now = datetime.utcnow()
        expired_rt = pyjwt.encode(
            {
                "sub": 1,
                "type": "refresh",
                "iat": int((now - timedelta(days=8)).timestamp()),
                "exp": int((now - timedelta(days=1)).timestamp()),
            },
            flask_app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        r = client.post("/api/auth/refresh", json={"refresh_token": expired_rt})
        assert r.status_code == 401

    def test_missing_refresh_token_field_returns_422(self, client):
        """Body missing refresh_token field → 422 Validation failed."""
        r = client.post("/api/auth/refresh", json={"oops": "wrong_field"})
        assert r.status_code == 422


# ══════════════════════════════════════════════
# § 4.2  Rate Limiting & Input Validation
# ══════════════════════════════════════════════

class TestRateLimiting:
    """§ 4.2 (a) — Max 5 attempts per minute per IP on /api/auth/token."""

    def test_sixth_attempt_is_rate_limited(self, client):
        """
        After 5 requests the 6th must return 429 Too Many Requests.

        The fixture resets the limiter before this test, giving us a clean
        counter.  All requests from the Flask test client share IP 127.0.0.1,
        so 5 failed attempts exhaust the bucket for that IP.
        """
        for attempt in range(5):
            r = client.post(
                "/api/auth/token",
                json={"username": "wrong", "password": "bad"},
            )
            # Each attempt is a bad credential → 401 (or earlier validation → 422)
            assert r.status_code in (401, 422), \
                f"Attempt {attempt+1}: unexpected {r.status_code}"

        # The 6th attempt must now be rate-limited
        r6 = client.post(
            "/api/auth/token",
            json={"username": "wrong", "password": "bad"},
        )
        assert r6.status_code == 429, \
            f"Expected 429 on 6th attempt, got {r6.status_code}: {r6.get_data(as_text=True)}"

    def test_rate_limit_response_contains_error_message(self, client):
        """
        The 429 response body must contain an informative error message,
        not a bare HTML page or empty body.
        """
        for _ in range(5):
            client.post(
                "/api/auth/token",
                json={"username": "x", "password": "y"},
            )

        r = client.post(
            "/api/auth/token",
            json={"username": "x", "password": "y"},
        )
        assert r.status_code == 429
        text = r.get_data(as_text=True).lower()
        assert any(kw in text for kw in ["too many", "rate", "limit", "attempts"]), \
            f"Rate-limit response missing expected message: {text[:200]}"


class TestInputValidation:
    """§ 4.2 (b, c) — Marshmallow schema validation and oversized/malformed input."""

    # ── /api/auth/token ───────────────────────

    def test_missing_username_returns_422(self, client):
        """
        Body missing 'username' must return 422 Unprocessable Entity with
        a field-level error in the 'details' key.
        Demonstrates § 4.2 (c): malformed input is rejected with HTTP 422.
        """
        r = client.post("/api/auth/token", json={"password": "abc"})
        assert r.status_code == 422
        body = r.get_json()
        assert "details" in body
        assert "username" in body["details"]

    def test_missing_password_returns_422(self, client):
        """Body missing 'password' → 422 with 'password' in details."""
        r = client.post("/api/auth/token", json={"username": "admin"})
        assert r.status_code == 422
        assert "password" in r.get_json()["details"]

    def test_both_fields_missing_returns_422(self, client):
        """Empty JSON object {} → 422 with both fields flagged in 'details'."""
        r = client.post("/api/auth/token", json={})
        assert r.status_code == 422
        details = r.get_json()["details"]
        assert "username" in details
        assert "password" in details

    def test_empty_body_returns_400(self, client):
        """
        Non-JSON (or empty) body → 400 Bad Request.
        Demonstrates § 4.2 (c): malformed input rejected with HTTP 400.
        """
        r = client.post(
            "/api/auth/token",
            data="",
            content_type="text/plain",
        )
        assert r.status_code == 400

    def test_form_encoded_body_returns_400(self, client):
        """
        Form-encoded body when JSON is expected → 400 Bad Request.
        The API only accepts application/json.
        """
        r = client.post(
            "/api/auth/token",
            data={"username": "admin", "password": "admin123"},
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 400

    def test_oversized_username_returns_422(self, client):
        """
        Username exceeding 150 characters must be rejected with 422.
        Verifies that the Length(max=150) validator fires before the DB
        is touched, preventing oversized-input DoS.
        """
        r = client.post(
            "/api/auth/token",
            json={"username": "A" * 151, "password": "admin123"},
        )
        assert r.status_code == 422
        assert "username" in r.get_json()["details"]

    def test_oversized_password_returns_422(self, client):
        """Password > 150 chars → 422."""
        r = client.post(
            "/api/auth/token",
            json={"username": "admin", "password": "P" * 151},
        )
        assert r.status_code == 422
        assert "password" in r.get_json()["details"]

    def test_extremely_large_payload_returns_4xx(self, client):
        """
        A 1 MB payload must be rejected with a 4xx status code.
        Either Flask's MAX_CONTENT_LENGTH (413) or Marshmallow's Length
        validator (422) catches it; either is acceptable.
        """
        huge = "X" * 1_000_000
        r = client.post(
            "/api/auth/token",
            json={"username": huge, "password": huge},
        )
        assert 400 <= r.status_code < 500, \
            f"Expected 4xx for 1 MB payload, got {r.status_code}"

    def test_null_username_returns_422(self, client):
        """JSON null for a required string field → 422."""
        r = client.post(
            "/api/auth/token",
            json={"username": None, "password": "admin123"},
        )
        assert r.status_code == 422

    # ── /api/transfer ─────────────────────────

    def test_transfer_negative_amount_returns_422(self, client):
        """
        Negative amount rejected by TransferSchema Range(min=0.01) → 422.
        'details' must identify the 'amount' field.
        """
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": -50.0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422
        assert "amount" in r.get_json()["details"]

    def test_transfer_zero_amount_returns_422(self, client):
        """Amount of exactly 0 rejected (min=0.01)."""
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_transfer_amount_above_max_returns_422(self, client):
        """Amount above 1,000,000 rejected by Range(max=1_000_000) → 422."""
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": 1_000_001},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_transfer_oversized_memo_returns_422(self, client):
        """Memo > 200 chars rejected by Length(max=200) → 422."""
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": 100, "memo": "M" * 201},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422

    def test_transfer_missing_to_account_returns_422(self, client):
        """Missing required 'to_account' → 422 with field error."""
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"amount": 100},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 422
        assert "to_account" in r.get_json()["details"]

    def test_transfer_unauthenticated_returns_401(self, client):
        """Transfer endpoint without a JWT must return 401."""
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": 100},
        )
        assert r.status_code == 401

    def test_valid_transfer_request_accepted(self, client):
        """Well-formed authenticated request must return 202 Accepted."""
        token = _access_token(client)
        r = client.post(
            "/api/transfer",
            json={"to_account": "8TB-999999", "amount": 50.00, "memo": "Lunch"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 202


# ══════════════════════════════════════════════
# Edge / integration cases
# ══════════════════════════════════════════════

class TestEdgeCases:
    """Security regression and integration checks."""

    def test_extra_json_fields_are_ignored(self, client):
        """
        Extra JSON fields (including 'role') must be silently ignored.
        An attacker cannot self-assign the 'admin' role via the request body.
        """
        r = client.post(
            "/api/auth/token",
            json={
                "username": "admin",
                "password": "admin123",
                "role": "admin",          # ← ignored
                "extra_field": "ignored",
            },
        )
        assert r.status_code == 200

    def test_profile_response_never_contains_password(self, client):
        """Regression: password must NEVER appear in any profile API response."""
        token = _access_token(client)
        r = client.get(
            "/api/user/profile",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = r.get_json()
        assert "password" not in body
        for key in body:
            assert "pass" not in key.lower()

    def test_admin_stats_returns_expected_aggregates(self, client):
        """Admin stats response must contain all three aggregate keys."""
        token = _access_token(client)
        r = client.get(
            "/api/admin/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = r.get_json()["data"]
        for key in ("total_users", "total_transactions", "total_volume"):
            assert key in data, f"Missing aggregate key: '{key}'"

    def test_access_token_carries_correct_claims(self, client):
        """
        Decode the issued access token and verify all expected claims are
        present and contain the right values.
        """
        r = _get_token(client, "admin", "admin123")
        at = r.get_json()["access_token"]
        payload = pyjwt.decode(
            at,
            flask_app.config["JWT_SECRET"],
            algorithms=["HS256"],
        )
        assert payload["type"] == "access"
        assert payload["role"] == "admin"
        assert "sub" in payload
        assert "exp" in payload
        assert "iat" in payload
        # Lifetime must equal JWT_ACCESS_EXPIRES
        assert payload["exp"] - payload["iat"] == flask_app.config["JWT_ACCESS_EXPIRES"]
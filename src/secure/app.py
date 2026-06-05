"""
app.py — Secure version
Changes vs. original:
  - SECRET_KEY sourced from environment only; no hardcoded fallback [FIX: session hardening]
  - DEBUG=False — prevents stack-trace leakage on error pages [FIX: session hardening]
  - Session cookie flags: HttpOnly, Secure, SameSite=Strict [FIX: session hardening]
  - 15-minute idle session timeout enforced in before_request [FIX: session hardening]
  - after_request hook adds CSP, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, and Referrer-Policy headers [FIX: CSP & security headers]
  - CSRF token generation lives here so it is available app-wide [FIX: CSRF protection]
"""

import os
import secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, session, request, g

from database import init_db, seed_db, DATABASE_PATH
from csrf import generate_csrf_token, validate_csrf_token

app = Flask(__name__)

# ---------------------------------------------------------------------------
# [FIX: session hardening] Secret key
# Must be supplied via the SECRET_KEY environment variable — no hardcoded
# fallback.  A missing key at startup raises an error rather than silently
# using a weak value that an attacker could guess.
# ---------------------------------------------------------------------------
secret = os.environ.get('SECRET_KEY')
if not secret:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = secret

# ---------------------------------------------------------------------------
# [FIX: session hardening] Cookie security flags
#   HttpOnly   — JS cannot read the session cookie (mitigates XSS cookie theft)
#   Secure     — cookie only sent over HTTPS (prevents cleartext sniffing)
#   SameSite   — Strict blocks the cookie on cross-site requests (extra CSRF layer)
# ---------------------------------------------------------------------------
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# [FIX: session hardening] Disable debug mode — never expose tracebacks in production
app.config['DEBUG'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# Session idle timeout (seconds) — 15 minutes
SESSION_TIMEOUT = 15 * 60


# ---------------------------------------------------------------------------
# [FIX: CSRF protection] CSRF token helpers live in csrf.py to avoid
# circular imports. Register generate_csrf_token as a Jinja2 global so
# every template can call {{ csrf_token() }} without an explicit import.
# ---------------------------------------------------------------------------
app.jinja_env.globals['csrf_token'] = generate_csrf_token


# ---------------------------------------------------------------------------
# [FIX: session hardening] Idle timeout enforcement
# ---------------------------------------------------------------------------

@app.before_request
def enforce_session_timeout():
    """
    If the user has been idle for more than SESSION_TIMEOUT seconds, wipe
    the session and redirect them to the login page.  This limits the window
    of opportunity for session hijacking.
    """
    # Skip enforcement for the login / register / static pages
    if request.endpoint in ('auth.login', 'auth.register', 'static', None):
        return

    last_active = session.get('_last_active')
    if last_active:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last_active)).total_seconds()
        if elapsed > SESSION_TIMEOUT:
            session.clear()
            from flask import redirect, url_for
            return redirect(url_for('auth.login'))

    # Refresh the timestamp on every authenticated request
    if 'user_id' in session:
        session['_last_active'] = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# [FIX: CSP & security headers] Security response headers
# Applied to every response via after_request.
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    """
    Attach security headers to every HTTP response.

    Content-Security-Policy:
      - default-src 'self'    — only allow resources from our own origin
      - script-src 'self'     — no inline scripts, no external JS (blocks XSS)
      - style-src 'self' https://fonts.googleapis.com — allow Google Fonts CSS
      - font-src 'self' https://fonts.gstatic.com     — allow Google Fonts files
      - img-src 'self' data:  — allow local images and data URIs
      - frame-ancestors 'none' — redundant with X-Frame-Options but belt+braces

    X-Frame-Options: DENY
      Prevents the page being embedded in an iframe (clickjacking defence).

    X-Content-Type-Options: nosniff
      Tells the browser not to MIME-sniff responses — prevents content-type
      confusion attacks (e.g. serving a JS file as text/plain).

    Strict-Transport-Security:
      Enforces HTTPS for 1 year including subdomains; preload-ready.
      Only effective once the site is served over HTTPS.

    Referrer-Policy: strict-origin-when-cross-origin
      Sends the full path on same-origin requests but only the origin on
      cross-origin ones, reducing information leakage in Referer headers.
    """
    # [FIX: output encoding & CSP]
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    # [FIX: session hardening / security headers]
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    # [FIX: session hardening / security headers]
    # no-referrer: never send the Referer header — prevents leaking internal URLs
    # to third-party sites (e.g. when a user clicks an external link from a
    # page that contains a session token or sensitive path in the URL).
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.transfer import transfer_bp
from routes.transactions import transactions_bp
from routes.admin import admin_bp
from routes.profile import profile_bp
from routes.api import api_bp

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(transfer_bp)
app.register_blueprint(transactions_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(api_bp)


# ---------------------------------------------------------------------------
# Error handlers — no stack traces exposed to the client
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    # [FIX: authorization] Return a clean 403 page — never expose internals
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', error='Page not found'), 404


@app.errorhandler(500)
def server_error(e):
    # [FIX: session hardening] Never expose tracebacks to the browser
    return render_template('500.html', error='An internal error occurred'), 500


if __name__ == '__main__':
    if not os.path.exists(DATABASE_PATH):
        print(f"[8TechBank-Secure] DB not found at {DATABASE_PATH}. Initializing...")
        init_db()
        seed_db()
    else:
        print(f"[8TechBank-Secure] DB found at {DATABASE_PATH}. Skipping init.")

    # [FIX: session hardening] debug=False in production; use a proper WSGI server
    app.run(host='0.0.0.0', port=5000, debug=False)

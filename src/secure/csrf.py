"""
csrf.py — CSRF token helpers extracted to avoid circular imports.
app.py and all route files import from here instead of from each other.
"""

import secrets
from flask import session, request


def generate_csrf_token() -> str:
    """Return the session CSRF token, creating one if absent."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token() -> bool:
    """
    Compare submitted token against session token using constant-time
    comparison to prevent timing attacks.
    """
    session_token = session.get('csrf_token', '')
    form_token = request.form.get('csrf_token', '')
    if not session_token or not form_token:
        return False
    return secrets.compare_digest(session_token, form_token)

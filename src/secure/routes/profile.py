"""
routes/profile.py — Secure version
Changes vs. original:
  - CSRF token validated on POST [FIX: CSRF protection]
  - user_id from session only — never from request [FIX: authorization / IDOR]
  - All queries parameterized [FIX: SQL injection]
  - display_name stored as-is (Jinja2 auto-escapes on render — | safe removed)
    [FIX: output encoding & CSP]
"""

from flask import Blueprint, session, redirect, url_for, render_template, request
from database import query_one, execute_write
from csrf import validate_csrf_token

profile_bp = Blueprint('profile', __name__)


@profile_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # [FIX: authorization / IDOR] user_id always from session
    user_id = session['user_id']
    error = None
    success = None

    if request.method == 'POST':
        # [FIX: CSRF protection] Reject forged cross-origin form submissions
        if not validate_csrf_token():
            error = 'Invalid request. Please try again.'
            user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
            return render_template('profile.html', user=user, error=error, success=None)

        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip()

        if not display_name or not email:
            error = 'Display name and email are required.'
        else:
            try:
                # [FIX: SQL injection] Parameterized UPDATE — values bound via ?
                # [FIX: output encoding & CSP] We store the raw value; Jinja2
                #   auto-escapes it on render (| safe filter has been removed from
                #   the template), so stored HTML/JS is never executed in the browser.
                execute_write(
                    "UPDATE users SET display_name = ?, email = ? WHERE id = ?",
                    (display_name, email, user_id)
                )
                session['display_name'] = display_name
                success = 'Profile updated successfully.'
            except Exception:
                error = 'Update failed. Please try again.'

    # [FIX: SQL injection] Parameterized SELECT
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    return render_template('profile.html', user=user, error=error, success=success)

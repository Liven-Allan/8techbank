"""
routes/dashboard.py — Secure version
Changes vs. original:
  - All queries use parameterized ? placeholders [FIX: SQL injection]
  - user_id always taken from session, never from request [FIX: authorization / IDOR]
"""

from flask import Blueprint, session, redirect, url_for, render_template
from database import query_one, query_all

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # [FIX: authorization / IDOR] user_id sourced exclusively from the server-side
    #   session — the client cannot influence which account is displayed.
    user_id = session['user_id']

    # [FIX: SQL injection] Parameterized query — user_id bound via ?, not concatenated
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    # [FIX: SQL injection] Parameterized query with two bound parameters
    txns = query_all(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.timestamp DESC LIMIT 5",
        (user_id, user_id)
    )

    return render_template('dashboard.html', user=user, transactions=txns)

"""
routes/admin.py — Secure version
Changes vs. original:
  - Role check enforced: session['role'] must equal 'admin'; any other
    authenticated user gets a 403 [FIX: authorization — admin role check]
  - All queries use parameterized LIKE / SELECT [FIX: SQL injection]
  - Search term sanitized via parameterized binding, not string concat
    [FIX: SQL injection]
"""

from flask import Blueprint, session, redirect, url_for, render_template, request, abort
from database import query_all

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin')
def admin():
    # [FIX: authorization — admin role check]
    # Step 1: must be authenticated
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # Step 2: must hold the 'admin' role — any regular user is denied with 403.
    #   The original code skipped this check entirely, so any logged-in user
    #   could access the full admin panel.
    if session.get('role') != 'admin':
        abort(403)

    search = request.args.get('search', '').strip()

    if search:
        # [FIX: SQL injection] LIKE pattern built with parameterized binding.
        #   The % wildcards are added in Python (safe), the user-supplied value
        #   is passed as a bound parameter — the DB driver handles escaping.
        pattern = f'%{search}%'
        users = query_all(
            "SELECT * FROM users "
            "WHERE username LIKE ? OR email LIKE ? "
            "ORDER BY id",
            (pattern, pattern)
        )
    else:
        users = query_all("SELECT * FROM users ORDER BY id")

    # [FIX: SQL injection] No parameterization needed here (no user input),
    #   but using the safe helper for consistency.
    txns = query_all(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "ORDER BY t.timestamp DESC LIMIT 50"
    )

    return render_template('admin.html', users=users, transactions=txns, search=search)

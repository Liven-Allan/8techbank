from flask import Blueprint, session, redirect, url_for, render_template, request
from database import raw_query

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin')
def admin():
    # VULN: Broken Access Control — role not verified for admin route
    # Only checks that a session exists, not that the user is an admin
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    search = request.args.get('search', '')

    if search:
        # VULN: SQL Injection — raw string concatenation
        users = raw_query(
            "SELECT * FROM users WHERE username LIKE '%" + search + "%' "
            "OR email LIKE '%" + search + "%' ORDER BY id"
        )
    else:
        users = raw_query("SELECT * FROM users ORDER BY id")

    # All transactions for the log
    txns = raw_query(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "ORDER BY t.timestamp DESC LIMIT 50"
    )

    return render_template('admin.html', users=users, transactions=txns, search=search)

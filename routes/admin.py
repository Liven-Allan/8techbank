from flask import Blueprint, session, redirect, url_for, render_template, request, abort, make_response
from database import get_db

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin')
def admin():
    # Require authentication
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # Enforce role-based access control: only admin users may view this page.
    if session.get('role') != 'admin':
        # Authenticated but not authorised — return 403 Forbidden.
        return abort(403)

    search = request.args.get('search', '')

    conn = get_db()
    if search:
        like = f"%{search}%"
        users = conn.execute(
            "SELECT * FROM users WHERE username LIKE ? OR email LIKE ? ORDER BY id",
            (like, like),
        ).fetchall()
    else:
        users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()

    # All transactions for the log (limit 50)
    txns = conn.execute(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "ORDER BY t.timestamp DESC LIMIT 50"
    ).fetchall()

    conn.close()

    resp = make_response(render_template('admin.html', users=users, transactions=txns, search=search))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

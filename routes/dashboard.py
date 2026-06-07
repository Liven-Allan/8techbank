from flask import Blueprint, session, redirect, url_for, render_template, make_response
from database import raw_query, get_db

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']

    # Use parameterised queries to avoid SQL injection
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    # Recent 5 transactions (sent or received)
    txns = conn.execute(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.timestamp DESC LIMIT 5",
        (user_id, user_id),
    ).fetchall()

    conn.close()

    # Render with strict no-cache headers so browsers know not to cache sensitive pages.
    resp = make_response(render_template('dashboard.html', user=user, transactions=txns))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

from flask import Blueprint, session, redirect, url_for, render_template
from database import raw_query

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']

    # VULN: SQL Injection — raw string concatenation
    user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    # Recent 5 transactions (sent or received)
    # VULN: SQL Injection — raw string concatenation
    txns = raw_query(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "WHERE t.sender_id=" + str(user_id) + " OR t.receiver_id=" + str(user_id) + " "
        "ORDER BY t.timestamp DESC LIMIT 5"
    )

    return render_template('dashboard.html', user=user, transactions=txns)

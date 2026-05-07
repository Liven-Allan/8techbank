from flask import Blueprint, session, redirect, url_for, render_template, request
from database import raw_query

transactions_bp = Blueprint('transactions', __name__)

PER_PAGE = 10


@transactions_bp.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # VULN: IDOR — no ownership verification on user_id param
    # Any logged-in user can view any other user's transactions by changing user_id
    user_id = request.args.get('user_id', session['user_id'])

    page = int(request.args.get('page', 1))
    offset = (page - 1) * PER_PAGE

    # VULN: SQL Injection — raw string concatenation
    txns = raw_query(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "WHERE t.sender_id=" + str(user_id) + " OR t.receiver_id=" + str(user_id) + " "
        "ORDER BY t.timestamp DESC "
        "LIMIT " + str(PER_PAGE) + " OFFSET " + str(offset)
    )

    # Count total for pagination
    # VULN: SQL Injection — raw string concatenation
    count_row = raw_query(
        "SELECT COUNT(*) as cnt FROM transactions "
        "WHERE sender_id=" + str(user_id) + " OR receiver_id=" + str(user_id),
        fetchone=True
    )
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    # Fetch the viewed user's info
    # VULN: SQL Injection — raw string concatenation
    viewed_user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    return render_template(
        'transactions.html',
        transactions=txns,
        page=page,
        total_pages=total_pages,
        user_id=user_id,
        viewed_user=viewed_user,
        session_user_id=session['user_id']
    )

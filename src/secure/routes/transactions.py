"""
routes/transactions.py — Secure version
Changes vs. original:
  - IDOR fixed: user_id is always taken from session['user_id'], never from
    request.args — a user can only ever see their own transactions
    [FIX: authorization / IDOR]
  - All queries use parameterized ? placeholders [FIX: SQL injection]
"""

from flask import Blueprint, session, redirect, url_for, render_template, request, abort
from database import query_all, query_one

transactions_bp = Blueprint('transactions', __name__)

PER_PAGE = 10


@transactions_bp.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    # [FIX: authorization / IDOR] If the caller supplies a user_id query param
    #   that does NOT match their own session, return 403 Forbidden immediately.
    #   This mirrors the PDF requirement: "the IDOR exploit now returns a 403".
    #   We do NOT silently swap it out — we actively reject the attempt so it
    #   is visible in logs and clearly denied to the attacker.
    requested_uid = request.args.get('user_id')
    if requested_uid is not None and str(requested_uid) != str(session['user_id']):
        abort(403)   # explicit 403 for attempted IDOR

    user_id = session['user_id']

    page = max(1, int(request.args.get('page', 1)))
    offset = (page - 1) * PER_PAGE

    # [FIX: SQL injection] All parameters bound via ?, never concatenated
    txns = query_all(
        "SELECT t.*, "
        "s.display_name AS sender_name, s.account_number AS sender_acct, "
        "r.display_name AS receiver_name, r.account_number AS receiver_acct "
        "FROM transactions t "
        "JOIN users s ON t.sender_id = s.id "
        "JOIN users r ON t.receiver_id = r.id "
        "WHERE t.sender_id = ? OR t.receiver_id = ? "
        "ORDER BY t.timestamp DESC "
        "LIMIT ? OFFSET ?",
        (user_id, user_id, PER_PAGE, offset)
    )

    # [FIX: SQL injection] Parameterized COUNT query
    count_row = query_one(
        "SELECT COUNT(*) AS cnt FROM transactions "
        "WHERE sender_id = ? OR receiver_id = ?",
        (user_id, user_id)
    )
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    # [FIX: SQL injection] Parameterized user lookup
    viewed_user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    return render_template(
        'transactions.html',
        transactions=txns,
        page=page,
        total_pages=total_pages,
        user_id=user_id,
        viewed_user=viewed_user,
        session_user_id=user_id,
    )

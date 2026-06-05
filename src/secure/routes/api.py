"""
routes/api.py — Secure version
Changes vs. original:
  - Parameterized query [FIX: SQL injection]
  - Password field removed from API response [FIX: sensitive data exposure]
  - user_id from session only [FIX: authorization / IDOR]
"""

from flask import Blueprint, session, jsonify
from database import query_one

api_bp = Blueprint('api', __name__)


@api_bp.route('/api/user/profile')
def api_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # [FIX: authorization / IDOR] Always use session identity — never a URL parameter
    user_id = session['user_id']

    # [FIX: SQL injection] Parameterized query
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # [FIX: sensitive data exposure] The 'password' field is intentionally omitted.
    #   Even a bcrypt hash should not be sent to clients — it could be used for
    #   offline cracking or enable enumeration attacks.
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'display_name': user['display_name'],
        'account_number': user['account_number'],
        'balance': user['balance'],
        'role': user['role'],
        'created_at': user['created_at'],
        # password intentionally excluded
    })

from flask import Blueprint, session, redirect, url_for, jsonify
from database import raw_query

api_bp = Blueprint('api', __name__)


@api_bp.route('/api/user/profile')
def api_user_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_id = session['user_id']

    # VULN: SQL Injection — raw string concatenation
    # VULN: Sensitive data exposure — plaintext password leaked in API response
    user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Return full DB row including plaintext password — intentional data leak
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'display_name': user['display_name'],
        'account_number': user['account_number'],
        'balance': user['balance'],
        'role': user['role'],
        'created_at': user['created_at'],
        # VULN: Sensitive data exposure — plaintext password leaked in API response
        'password': user['password'],
    })

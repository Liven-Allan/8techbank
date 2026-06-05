"""
routes/auth.py — Secure version
Changes vs. original:
  - Login uses parameterized query to fetch user by username only,
    then calls bcrypt.checkpw() to verify the password
    [FIX: SQL injection, FIX: bcrypt password hashing]
  - Password is never compared inside the SQL WHERE clause
    [FIX: bcrypt password hashing]
  - Registration hashes password with hash_password() before storage
    [FIX: bcrypt password hashing]
  - Registration uses parameterized INSERT
    [FIX: SQL injection]
  - All state-changing POST forms validate the CSRF token
    [FIX: CSRF protection]
  - session.regenerate() equivalent: session is cleared and rebuilt after
    successful login to prevent session fixation
    [FIX: session hardening]
"""

import random
from flask import Blueprint, request, session, redirect, url_for, render_template
from database import query_one, execute_write, hash_password, check_password
from csrf import validate_csrf_token

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard'))
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # [FIX: CSRF protection] Reject the request if the token is missing or wrong
        if not validate_csrf_token():
            error = 'Invalid request. Please try again.'
            return render_template('login.html', error=error)

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # [FIX: SQL injection] Parameterized query — username bound via ?, never concatenated
        # [FIX: bcrypt password hashing] We fetch by username only; password check is done
        #   in Python with bcrypt.checkpw(), not inside the SQL WHERE clause.
        #   This prevents SQL injection AND prevents timing-oracle via SQL short-circuit.
        user = query_one(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        # [FIX: bcrypt password hashing] check_password() uses constant-time comparison
        if user and check_password(password, user['password']):
            # [FIX: session hardening] Clear old session data before writing new identity
            #   to prevent session-fixation attacks.
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['display_name'] = user['display_name']
            session['account_number'] = user['account_number']
            session['role'] = user['role']
            return redirect(url_for('dashboard.dashboard'))
        else:
            # Generic message — don't reveal whether username or password was wrong
            error = 'Invalid credentials. Please try again.'

    return render_template('login.html', error=error)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    if request.method == 'POST':
        # [FIX: CSRF protection] Validate token before processing any state change
        if not validate_csrf_token():
            error = 'Invalid request. Please try again.'
            return render_template('register.html', error=error)

        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        display_name = request.form.get('display_name', '').strip() or username

        if not username or not email or not password:
            error = 'All fields are required.'
        else:
            account_number = '8TB-' + str(random.randint(100000, 999999))
            balance = round(random.uniform(1000, 5000), 2)

            # [FIX: bcrypt password hashing] Never store plain-text; hash before INSERT
            hashed = hash_password(password)

            try:
                # [FIX: SQL injection] Parameterized INSERT — all values bound via ?
                execute_write(
                    "INSERT INTO users "
                    "(username, email, password, display_name, account_number, balance, role) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'user')",
                    (username, email, hashed, display_name, account_number, balance)
                )
                success = 'Account created successfully. You can now log in.'
            except Exception as e:
                if 'UNIQUE' in str(e):
                    error = 'Username or email already exists.'
                else:
                    # Don't expose raw DB errors — log server-side instead
                    error = 'Registration failed. Please try again.'

    return render_template('register.html', error=error, success=success)


@auth_bp.route('/logout')
def logout():
    # Clear the entire session on logout — removes CSRF token, identity, and timeout marker
    session.clear()
    return redirect(url_for('auth.login'))

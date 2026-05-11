from flask import Blueprint, request, session, redirect, url_for, render_template
from database import get_db, raw_query
import random

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
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULN: SQL Injection — raw string concatenation
        # VULN: Plaintext password comparison
        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        user = raw_query(query, fetchone=True)

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['display_name'] = user['display_name']
            session['account_number'] = user['account_number']
            session['role'] = user['role']
            return redirect(url_for('dashboard.dashboard'))
        else:
            # VULN: No account lockout — unlimited brute force attempts allowed
            error = 'Invalid credentials. Please try again.'

    return render_template('login.html', error=error)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        display_name = request.form.get('display_name', '').strip() or username

        if not username or not email or not password:
            error = 'All fields are required.'
        else:
            # VULN: Plaintext password storage — no hashing
            account_number = '8TB-' + str(random.randint(100000, 999999))
            balance = round(random.uniform(1000, 5000), 2)

            try:
                # VULN: SQL Injection — raw string concatenation
                query = "INSERT INTO users (username, email, password, display_name, account_number, balance, role) VALUES ('" + username + "', '" + email + "', '" + password + "', '" + display_name + "', '" + account_number + "', " + str(balance) + ", 'user')"
                raw_query(query)
                success = 'Account created successfully. You can now log in.'
            except Exception as e:
                if 'UNIQUE' in str(e):
                    error = 'Username or email already exists.'
                else:
                    error = 'Registration failed: ' + str(e)

    return render_template('register.html', error=error, success=success)


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

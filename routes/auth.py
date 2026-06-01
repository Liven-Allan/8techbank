from flask import Blueprint, request, session, redirect, url_for, render_template
from database import get_db, raw_query
import random
from extensions import limiter
import re
import unicodedata
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard.dashboard'))
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"], error_message="Too many login attempts. Please wait 60 seconds.")
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Normalize Unicode to avoid unusual grapheme abuses and ensure
        # length checks operate on a consistent representation.
        username = unicodedata.normalize('NFC', username)
        password = unicodedata.normalize('NFC', password)

        # Server-side input validation
        if username == '' or password == '':
            error = 'Fields cannot be empty'
            return render_template('login.html', error=error), 400

        if len(username) > 150 or len(password) > 150:
            error = 'Input too large'
            return render_template('login.html', error=error), 422

        # Disallow control characters, NUL bytes, and limit to allowed charset.
        if '\x00' in username or '\x00' in password:
            error = 'Invalid input'
            return render_template('login.html', error=error), 422

        # Only allow ASCII alphanumerics and a few safe punctuation characters.
        if not re.match(r'^[A-Za-z0-9_.-]{1,150}$', username):
            error = 'Invalid username format'
            return render_template('login.html', error=error), 422

        # Lookup user by username and verify hashed password
        conn = get_db()
        cur = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        if user and check_password_hash(user['password'], password):
            # Successful auth
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['display_name'] = user['display_name']
            session['account_number'] = user['account_number']
            session['role'] = user['role']
            conn.close()
            return redirect(url_for('dashboard.dashboard'))
        conn.close()

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

        # Server-side validation
        if not username or not email or not password:
            error = 'All fields are required.'
            return render_template('register.html', error=error), 400

        if len(username) > 150 or len(password) > 150 or len(email) > 254:
            error = 'Input too large'
            return render_template('register.html', error=error), 422

        # Simple email format check
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            error = 'Invalid email format'
            return render_template('register.html', error=error), 422

        if not username or not email or not password:
            error = 'All fields are required.'
        else:
            # VULN: Plaintext password storage — no hashing
            account_number = '8TB-' + str(random.randint(100000, 999999))
            balance = round(random.uniform(1000, 5000), 2)

            try:
                # Store hashed password using werkzeug
                hashed = generate_password_hash(password)
                conn = get_db()
                conn.execute('INSERT INTO users (username, email, password, display_name, account_number, balance, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
                             (username, email, hashed, display_name, account_number, balance, 'user'))
                conn.commit()
                conn.close()
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
    # Return a redirect with no-cache headers to reduce likelihood of the
    # browser showing a cached authenticated page when the user presses Back.
    resp = redirect(url_for('auth.login'))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

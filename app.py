import os
from flask import Flask, render_template, request
from database import init_db, seed_db, DATABASE_PATH
from extensions import limiter
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import RequestEntityTooLarge
import os

app = Flask(__name__)

# Secret configuration
# Prefer setting SECRET_KEY and JWT_SECRET via environment in production.
# For local development the existing default preserves test behaviour, but
# we emit a startup notice so maintainers are reminded to set a real secret.
app.secret_key = os.environ.get('SECRET_KEY', 'bank123')

# Disable debug mode by default. Enable by setting environment variable
# DEBUG=1 or DEBUG=true for local development only.
debug_env = os.environ.get('DEBUG', 'false').lower()
app.config['DEBUG'] = debug_env in ('1', 'true', 'yes')
app.config['PROPAGATE_EXCEPTIONS'] = False

if app.secret_key == 'bank123':
    # Friendly reminder rather than failing — keeps CI/tests working while
    # signalling maintainers this should be changed for production.
    print("[Warning] Using default weak SECRET_KEY. Set SECRET_KEY in environment for production.")

# Limit maximum request body size to avoid extremely large payloads (bytes)
# Default to 16KiB; can be overridden via env `MAX_CONTENT_LENGTH`.
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024))

# JWT configuration
# Use a separate JWT secret where possible and keep it out of source control.
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', app.secret_key)
app.config['JWT_ALGORITHM'] = 'HS256'
# Access tokens expire in 15 minutes (900 seconds)
app.config['JWT_ACCESS_EXPIRES'] = int(os.environ.get('JWT_ACCESS_EXPIRES', 900))
# Refresh tokens expire in 7 days by default
app.config['JWT_REFRESH_EXPIRES'] = int(os.environ.get('JWT_REFRESH_EXPIRES', 7 * 24 * 3600))

# Initialize extensions
# If the app is deployed behind a reverse proxy (nginx, docker, cloud load
# balancer), the client's real IP is forwarded in the X-Forwarded-For header.
# Apply ProxyFix before initializing the limiter so get_remote_address() sees
# the correct client IP and rate-limiting works per-client as expected.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Allow configuring the limiter storage backend via env (defaults to in-memory
# which is fine for local dev). In production set to a shared store like Redis
# e.g. export RATELIMIT_STORAGE_URL=redis://redis:6379
app.config.setdefault("RATELIMIT_STORAGE_URL", os.environ.get("RATELIMIT_STORAGE_URL", "memory://"))

limiter.init_app(app)

# Register blueprints
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.transfer import transfer_bp
from routes.transactions import transactions_bp
from routes.admin import admin_bp
from routes.profile import profile_bp
from routes.api import api_bp

app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(transfer_bp)
app.register_blueprint(transactions_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(api_bp)

# ----- VULNERABLE SEARCH ROUTE (Reflected XSS) for Task 2 -----
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: user input rendered without any encoding
    return f'<h2>Search Results for: {query}</h2><p>No results found.</p>'
# ----- END SEARCH ROUTE -----

# VULNERABLE IDOR endpoint – no authorization check
@app.route('/account/<int:account_id>')
def view_account(account_id):
    from database import raw_query
    account = raw_query(f"SELECT * FROM users WHERE id={account_id}", fetchone=True)
    if not account:
        return "Account not found", 404
    return f"""
    <h2>Account Details (ID: {account_id})</h2>
    <p>Username: {account['username']}</p>
    <p>Email: {account['email']}</p>
    <p>Balance: ${account['balance']}</p>
    <p>Account Number: {account['account_number']}</p>
    <p>Role: {account['role']}</p>
    """

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', error=str(e)), 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    tb = traceback.format_exc()
    return render_template('500.html', error=str(e), traceback=tb), 500


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(e):
    return render_template('500.html', error='Request payload too large.'), 413

if __name__ == '__main__':
    if not os.path.exists(DATABASE_PATH):
        print(f"[8TechBank] DB not found at {DATABASE_PATH}. Initializing...")
        init_db()
        seed_db()
    else:
        print(f"[8TechBank] DB found at {DATABASE_PATH}. Skipping init.")


    app.run(host='0.0.0.0', port=5000, debug=True)
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])

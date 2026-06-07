import os
from flask import Flask, render_template, request
from database import init_db, seed_db, DATABASE_PATH

app = Flask(__name__)

# VULN: Weak secret key — hardcoded, trivially guessable
app.secret_key = os.environ.get('SECRET_KEY', 'bank123')

# VULN: DEBUG=True exposes full Python tracebacks on error pages
app.config['DEBUG'] = True
app.config['PROPAGATE_EXCEPTIONS'] = False

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

if __name__ == '__main__':
    if not os.path.exists(DATABASE_PATH):
        print(f"[8TechBank] DB not found at {DATABASE_PATH}. Initializing...")
        init_db()
        seed_db()
    else:
        print(f"[8TechBank] DB found at {DATABASE_PATH}. Skipping init.")

    app.run(host='0.0.0.0', port=5000, debug=True)
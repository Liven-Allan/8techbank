import os
from flask import Flask, render_template
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


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', error=str(e)), 404


@app.errorhandler(500)
def server_error(e):
    import traceback
    tb = traceback.format_exc()
    return render_template('500.html', error=str(e), traceback=tb), 500


if __name__ == '__main__':
    # Auto-initialize DB if missing — works on first docker compose up
    if not os.path.exists(DATABASE_PATH):
        print(f"[8TechBank] DB not found at {DATABASE_PATH}. Initializing...")
        init_db()
        seed_db()
    else:
        print(f"[8TechBank] DB found at {DATABASE_PATH}. Skipping init.")

    app.run(host='0.0.0.0', port=5000, debug=True)

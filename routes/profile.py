from flask import Blueprint, session, redirect, url_for, render_template, request
from database import raw_query, raw_query_write

profile_bp = Blueprint('profile', __name__)


@profile_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    error = None
    success = None

    if request.method == 'POST':
        display_name = request.form.get('display_name', '').strip()
        email = request.form.get('email', '').strip()

        if not display_name or not email:
            error = 'Display name and email are required.'
        else:
            try:
                # VULN: SQL Injection — raw string concatenation
                # VULN: XSS — display_name stored and rendered unsanitized with | safe
                raw_query_write(
                    "UPDATE users SET display_name='" + display_name +
                    "', email='" + email + "' WHERE id=" + str(user_id)
                )
                session['display_name'] = display_name
                success = 'Profile updated successfully.'
            except Exception as e:
                error = 'Update failed: ' + str(e)

    # VULN: SQL Injection — raw string concatenation
    user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    return render_template('profile.html', user=user, error=error, success=success)

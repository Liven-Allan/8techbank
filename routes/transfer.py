from flask import Blueprint, session, redirect, url_for, render_template, request
from database import raw_query, raw_query_write

transfer_bp = Blueprint('transfer', __name__)


@transfer_bp.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    error = None
    success = None
    confirm = False
    form_data = {}

    user_id = session['user_id']
    # VULN: SQL Injection — raw string concatenation
    user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    if request.method == 'POST':
        action = request.form.get('action', '')
        recipient_account = request.form.get('recipient_account', '').strip()
        amount_str = request.form.get('amount', '0').strip()
        memo = request.form.get('memo', '').strip()

        form_data = {
            'recipient_account': recipient_account,
            'amount': amount_str,
            'memo': memo,
        }

        try:
            amount = float(amount_str)
        except ValueError:
            error = 'Invalid amount.'
            return render_template('transfer.html', user=user, error=error, form_data=form_data)

        if amount <= 0:
            error = 'Amount must be greater than zero.'
            return render_template('transfer.html', user=user, error=error, form_data=form_data)

        # VULN: SQL Injection — raw string concatenation
        recipient = raw_query(
            "SELECT * FROM users WHERE account_number='" + recipient_account + "'",
            fetchone=True
        )

        if not recipient:
            error = 'Recipient account not found.'
            return render_template('transfer.html', user=user, error=error, form_data=form_data)

        if action == 'preview':
            confirm = True
            return render_template('transfer.html', user=user, confirm=confirm,
                                   recipient=recipient, form_data=form_data, error=error)

        if action == 'confirm':
            # VULN: IDOR — no account ownership check before debit
            # Any logged-in user can specify any sender account_id in the form
            sender_id = request.form.get('sender_id', str(user_id))

            # VULN: SQL Injection — raw string concatenation
            sender = raw_query("SELECT * FROM users WHERE id=" + str(sender_id), fetchone=True)

            if not sender:
                error = 'Sender account not found.'
                return render_template('transfer.html', user=user, error=error, form_data=form_data)

            if sender['balance'] < amount:
                error = 'Insufficient funds in sender account.'
                return render_template('transfer.html', user=user, error=error, form_data=form_data)

            # Debit sender
            # VULN: SQL Injection — raw string concatenation
            raw_query_write(
                "UPDATE users SET balance=" + str(sender['balance'] - amount) +
                " WHERE id=" + str(sender['id'])
            )
            # Credit receiver
            # VULN: SQL Injection — raw string concatenation
            raw_query_write(
                "UPDATE users SET balance=" + str(recipient['balance'] + amount) +
                " WHERE id=" + str(recipient['id'])
            )
            # Record transaction — memo stored raw (XSS surface)
            # VULN: SQL Injection — raw string concatenation
            raw_query_write(
                "INSERT INTO transactions (sender_id, receiver_id, amount, memo) VALUES (" +
                str(sender['id']) + ", " + str(recipient['id']) + ", " + str(amount) +
                ", '" + memo + "')"
            )

            # Refresh session balance if own account was debited
            if str(sender['id']) == str(user_id):
                session['balance'] = sender['balance'] - amount

            success = f"Transfer of ${amount:.2f} to {recipient['display_name']} ({recipient['account_number']}) completed."
            # Reload user for updated balance
            user = raw_query("SELECT * FROM users WHERE id=" + str(user_id), fetchone=True)

    return render_template('transfer.html', user=user, error=error, success=success,
                           confirm=confirm, form_data=form_data)

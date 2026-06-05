"""
routes/transfer.py — Secure version
Changes vs. original:
  - CSRF token validated on every POST [FIX: CSRF protection]
  - sender_id taken exclusively from session; the form's sender_id hidden field
    is removed — no client-supplied sender is ever trusted [FIX: authorization / IDOR]
  - All queries use parameterized ? placeholders [FIX: SQL injection]
  - Balance update uses a single atomic SQL expression (balance - ?) rather
    than fetching the value into Python and writing it back, which prevents a
    TOCTOU race condition
"""

from flask import Blueprint, session, redirect, url_for, render_template, request
from database import query_one, query_all, execute_write
from csrf import validate_csrf_token

transfer_bp = Blueprint('transfer', __name__)


@transfer_bp.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    error = None
    success = None
    confirm = False
    form_data = {}

    # [FIX: authorization / IDOR] Always use the session identity — never accept
    #   a user-supplied sender ID.
    user_id = session['user_id']

    # [FIX: SQL injection] Parameterized lookup
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    if request.method == 'POST':
        # [FIX: CSRF protection] Validate before touching any state
        if not validate_csrf_token():
            error = 'Invalid request. Please try again.'
            return render_template('transfer.html', user=user, error=error, form_data={})

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

        # [FIX: SQL injection] Parameterized recipient lookup
        recipient = query_one(
            "SELECT * FROM users WHERE account_number = ?",
            (recipient_account,)
        )

        if not recipient:
            error = 'Recipient account not found.'
            return render_template('transfer.html', user=user, error=error, form_data=form_data)

        if recipient['id'] == user_id:
            error = 'Cannot transfer to your own account.'
            return render_template('transfer.html', user=user, error=error, form_data=form_data)

        if action == 'preview':
            confirm = True
            return render_template('transfer.html', user=user, confirm=confirm,
                                   recipient=recipient, form_data=form_data, error=error)

        if action == 'confirm':
            # [FIX: authorization / IDOR] The original code accepted sender_id from
            #   request.form, allowing any logged-in user to drain another account.
            #   We always debit the session-authenticated user — no form field consulted.
            sender = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

            if not sender:
                error = 'Sender account not found.'
                return render_template('transfer.html', user=user, error=error, form_data=form_data)

            if sender['balance'] < amount:
                error = 'Insufficient funds.'
                return render_template('transfer.html', user=user, error=error, form_data=form_data)

            # [FIX: SQL injection] Parameterized UPDATE; arithmetic done in SQL
            #   to avoid a TOCTOU race between the balance fetch and the write-back
            execute_write(
                "UPDATE users SET balance = balance - ? WHERE id = ?",
                (amount, sender['id'])
            )
            execute_write(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, recipient['id'])
            )

            # [FIX: SQL injection] Parameterized INSERT for transaction record
            execute_write(
                "INSERT INTO transactions (sender_id, receiver_id, amount, memo) "
                "VALUES (?, ?, ?, ?)",
                (sender['id'], recipient['id'], amount, memo)
            )

            success = (
                f"Transfer of ${amount:.2f} to {recipient['display_name']} "
                f"({recipient['account_number']}) completed."
            )
            # Reload user to show updated balance
            user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    return render_template('transfer.html', user=user, error=error, success=success,
                           confirm=confirm, form_data=form_data)

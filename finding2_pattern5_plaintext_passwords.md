# Finding 2 — Pattern 5: Plaintext Password Storage

**Assigned to:** Lutalo Allan
**Status:** Completed

---

## 3.2.1 Identification

| Field | Detail |
|---|---|
| **CWE** | CWE-256: Plaintext Storage of a Password |
| **OWASP Top 10 (2021)** | A02: Cryptographic Failures |
| **Files** | `database.py` lines 19–21 (definition); `routes/auth.py` lines 22 and 52 (usage); `routes/api.py` line 29 (exposure) |
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |

---

## 3.2.2 Vulnerable Code

**File: `database.py`, Lines 19–21**

```python
def md5_hash(password):
    # VULN: Plaintext password storage — no hashing applied
    return password
```

The function named `md5_hash` performs no hashing whatsoever — it returns the password string unchanged. All callers in `seed_db()` pass through plaintext values directly into the database.

**File: `routes/auth.py`, Line 52 — Registration**

```python
# VULN: Plaintext password storage — no hashing
query = "INSERT INTO users (username, email, password, display_name, account_number, balance, role) VALUES ('" \
        + username + "', '" + email + "', '" + password + "', ..."
```

The raw password submitted by the user is inserted directly into the `users.password` column with no transformation.

**File: `routes/auth.py`, Line 22 — Login**

```python
# VULN: Plaintext password comparison
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
```

Authentication compares the submitted password directly against the stored plaintext value.

**File: `routes/api.py`, Line 29 — API Exposure**

```python
# VULN: Sensitive data exposure — plaintext password leaked in API response
'password': user['password'],
```

The `/api/user/profile` endpoint returns the plaintext password in its JSON response, making it directly readable over the network.

All passwords, including the admin account (`admin123`), are stored as plaintext strings in the `users.password` column.

---

## 3.2.3 Security Impact

**Immediate full credential exposure on database breach.**
Unlike hashed passwords which require cracking effort, plaintext passwords are immediately usable. Any attacker who gains read access to the database — via SQL injection, a backup file, or direct access — obtains every user's password with zero additional effort.

**Credential reuse attacks.**
Users commonly reuse passwords across services. Plaintext exposure of `password123` from this application directly enables account takeover on email providers, other banking apps, and any other service where the user reused that password.

**API leaks passwords over the wire.**
The `/api/user/profile` endpoint returns `"password": "admin123"` in its JSON response. Any authenticated user can call this endpoint and retrieve their own plaintext password. Combined with other vulnerabilities (e.g., IDOR), an attacker could retrieve other users' passwords through the API alone — no database access required.

**No cracking step required.**
With MD5 or bcrypt, an attacker still needs to run a cracking tool. With plaintext storage, the attack is instantaneous and requires no computation, no wordlists, and no specialised tools.

**Admin account fully compromised.**
The seed admin account stores `admin123` in plaintext. Any database read — including via the SQL injection vulnerabilities present in this application — immediately yields full administrative credentials.

---

## 3.2.4 Proof of Concept

**Via the API (no database access needed):**

Step 1: Log in as any registered user (e.g., `user1` / `password123`).

Step 2: Call the profile API endpoint:

```
GET /api/user/profile
```

Step 3: The JSON response directly contains the plaintext password:

```json
{
  "id": 2,
  "username": "user1",
  "email": "user1@example.com",
  "password": "password123",
  ...
}
```

No cracking, no tools, no computation required.

**Via SQL Injection (database read):**

Step 1: Use the SQL injection vulnerability in the login form with payload:

```
username: ' OR 1=1 --
```

Step 2: Query the users table directly:

```sql
SELECT username, password FROM users;
```

Step 3: Result returns all credentials in plaintext:

```
admin      | admin123
user1      | password123
user2      | password123
user3      | password123
user4      | password123
user5      | password123
```

All credentials are immediately usable with no further steps.

---

## 3.2.5 Remediation

Replace plaintext storage with a purpose-built password hashing algorithm. **bcrypt**, **scrypt**, or **Argon2id** are all appropriate choices. These algorithms are intentionally slow, incorporate a unique salt per hash automatically, and are resistant to GPU-accelerated brute force.

**Recommended fix using bcrypt:**

```python
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
```

Update `routes/auth.py` registration to hash on store:

```python
# In register()
password_hash = hash_password(password)
# store password_hash instead of password
```

Update `routes/auth.py` login to verify instead of comparing directly:

```python
# In login()
user = get_user_by_username(username)  # fetch user first
if user and verify_password(password, user['password_hash']):
    # grant session
```

Remove the `password` field from the `/api/user/profile` response entirely — there is no legitimate reason to return a password (hashed or otherwise) in an API response.

Add `bcrypt` to `requirements.txt`:

```
bcrypt==4.1.3
```

The `rounds=12` parameter means each hash takes approximately 250 ms to compute, which is negligible for a single login but makes bulk cracking computationally infeasible. Rename the database column from `password` back to `password_hash` to reflect that it stores a hash, not a credential.

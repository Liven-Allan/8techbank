"""
database.py — Secure version
Changes vs. original:
  - md5_hash() replaced with bcrypt hashing (12 rounds) [FIX: bcrypt password hashing]
  - seed_db() uses parameterized queries instead of string concatenation [FIX: SQL injection]
  - raw_query() and raw_query_write() removed; all queries must use parameterized helpers
  - New helpers: query_one(), query_all(), execute_write() enforce parameterization everywhere
"""

import sqlite3
import random
import os
import bcrypt
from datetime import datetime, timedelta

DATABASE_PATH = os.environ.get('DATABASE_PATH', './data/8techbank.db')

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_db():
    """Return a sqlite3 connection with Row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Parameterized query helpers — replaces raw_query / raw_query_write
# [FIX: SQL injection] All callers must supply a params tuple; string
#   interpolation into SQL is never allowed.
# ---------------------------------------------------------------------------

def query_all(sql: str, params: tuple = ()):
    """Execute a SELECT and return all rows."""
    conn = get_db()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def query_one(sql: str, params: tuple = ()):
    """Execute a SELECT and return a single row (or None)."""
    conn = get_db()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def execute_write(sql: str, params: tuple = ()):
    """Execute an INSERT / UPDATE / DELETE with auto-commit."""
    conn = get_db()
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Password helpers
# [FIX: bcrypt password hashing] Plain-text storage and md5_hash() are gone.
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """
    Hash a plain-text password with bcrypt, cost factor 12.
    12 rounds balances security against brute-force with acceptable latency
    (≈ 250 ms on modern hardware), consistent with OWASP recommendations.
    """
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')


def check_password(plain: str, hashed: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.
    Uses bcrypt.checkpw() which is constant-time to prevent timing attacks.
    Never compare passwords directly with == or in SQL.
    """
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db():
    """Create tables from schema.sql (shared with original app)."""
    db_dir = os.path.dirname(os.path.abspath(DATABASE_PATH))
    os.makedirs(db_dir, exist_ok=True)
    conn = get_db()
    schema_path = os.path.join(_BASE_DIR, '..', '..', 'schema.sql')
    with open(schema_path, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("[8TechBank-Secure] Database schema initialized.")


def seed_db():
    """
    Insert seed users and transactions.
    [FIX: SQL injection] Every INSERT uses ? placeholders — no string concatenation.
    [FIX: bcrypt password hashing] Passwords are hashed before storage.
    """
    conn = get_db()

    users = [
        ('admin',  'admin@8techbank.com',  hash_password('admin123'),    'Administrator',  '8TB-000001', 99999.00, 'admin'),
        ('user1',  'user1@example.com',    hash_password('password123'), 'Alice Johnson',  '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user2',  'user2@example.com',    hash_password('password123'), 'Bob Martinez',   '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user3',  'user3@example.com',    hash_password('password123'), 'Carol Williams', '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user4',  'user4@example.com',    hash_password('password123'), 'David Chen',     '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user5',  'user5@example.com',    hash_password('password123'), 'Eva Patel',      '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
    ]

    # [FIX: SQL injection] Parameterized INSERT — values are bound via ?, never concatenated
    for u in users:
        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(username, email, password, display_name, account_number, balance, role) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            u
        )

    conn.commit()

    rows = conn.execute("SELECT id FROM users ORDER BY id").fetchall()
    ids = [r['id'] for r in rows]

    memos = [
        'Rent payment', 'Grocery reimbursement', 'Freelance invoice #1042',
        'Dinner split', 'Utility bill share', 'Birthday gift',
        'Loan repayment', 'Coffee', 'Concert tickets',
        'Monthly subscription', 'Parking fee', 'Book purchase',
        'Travel reimbursement', 'Gym membership', 'Online course fee',
        'Hardware purchase', 'Software license', 'Consulting fee',
        'Bonus transfer', 'Emergency fund', 'Tax refund share',
        'Project milestone payment',
    ]

    base_time = datetime.now() - timedelta(days=30)
    for i in range(22):
        sender_id = random.choice(ids)
        receiver_id = random.choice([x for x in ids if x != sender_id])
        amount = round(random.uniform(10, 800), 2)
        memo = memos[i % len(memos)]
        ts = (base_time + timedelta(hours=i * 13)).strftime('%Y-%m-%d %H:%M:%S')
        # [FIX: SQL injection] Parameterized INSERT
        conn.execute(
            "INSERT INTO transactions (sender_id, receiver_id, amount, memo, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (sender_id, receiver_id, amount, memo, ts)
        )

    conn.commit()
    conn.close()
    print("[8TechBank-Secure] Seed data injected.")

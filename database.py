import sqlite3
import random
import os
from datetime import datetime, timedelta

DATABASE_PATH = os.environ.get('DATABASE_PATH', './data/8techbank.db')

# Resolve schema.sql relative to this file's directory
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_db():
    """Return a raw sqlite3 connection to the database."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5_hash(password):
    # VULN: Plaintext password storage — no hashing applied
    return password


def init_db():
    """Create tables from schema.sql."""
    db_dir = os.path.dirname(os.path.abspath(DATABASE_PATH))
    os.makedirs(db_dir, exist_ok=True)
    conn = get_db()
    schema_path = os.path.join(_BASE_DIR, 'schema.sql')
    with open(schema_path, 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    print("[8TechBank] Database schema initialized.")


def seed_db():
    """Insert seed users and transactions."""
    conn = get_db()

    # Seed users
    users = [
        ('admin',  'admin@8techbank.com',  md5_hash('admin123'),    'Administrator',  '8TB-000001', 99999.00, 'admin'),
        ('user1',  'user1@example.com',    md5_hash('password123'), 'Alice Johnson',  '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user2',  'user2@example.com',    md5_hash('password123'), 'Bob Martinez',   '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user3',  'user3@example.com',    md5_hash('password123'), 'Carol Williams', '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user4',  'user4@example.com',    md5_hash('password123'), 'David Chen',     '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
        ('user5',  'user5@example.com',    md5_hash('password123'), 'Eva Patel',      '8TB-' + str(random.randint(100000, 999999)), round(random.uniform(500, 10000), 2), 'user'),
    ]

    for u in users:
        # VULN: SQL Injection — raw string concatenation
        query = "INSERT OR IGNORE INTO users (username, email, password, display_name, account_number, balance, role) VALUES ('" + u[0] + "', '" + u[1] + "', '" + u[2] + "', '" + u[3] + "', '" + u[4] + "', " + str(u[5]) + ", '" + u[6] + "')"
        conn.execute(query)

    conn.commit()

    # Fetch user IDs for transactions
    rows = conn.execute("SELECT id FROM users ORDER BY id").fetchall()
    ids = [r['id'] for r in rows]

    # Seed 20+ transactions
    memos = [
        'Rent payment', 'Grocery reimbursement', 'Freelance invoice #1042',
        'Dinner split', 'Utility bill share', 'Birthday gift',
        'Loan repayment', 'Coffee ☕', 'Concert tickets',
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
        # VULN: SQL Injection — raw string concatenation
        query = "INSERT INTO transactions (sender_id, receiver_id, amount, memo, timestamp) VALUES (" + str(sender_id) + ", " + str(receiver_id) + ", " + str(amount) + ", '" + memo + "', '" + ts + "')"
        conn.execute(query)

    conn.commit()
    conn.close()
    print("[8TechBank] Seed data injected.")


def raw_query(sql, fetchone=False):
    """Execute a raw SQL query and return results. No parameterization — intentional."""
    conn = get_db()
    try:
        cur = conn.execute(sql)
        conn.commit()
        if fetchone:
            return cur.fetchone()
        return cur.fetchall()
    except Exception as e:
        conn.close()
        raise e
    finally:
        conn.close()


def raw_query_write(sql):
    """Execute a raw write SQL query (INSERT/UPDATE/DELETE)."""
    conn = get_db()
    try:
        conn.execute(sql)
        conn.commit()
    finally:
        conn.close()

import sys
import os

# Ensure project root is on sys.path so imports like `from app import app` work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app

def run_tests():
    client = app.test_client()

    cases = [
        ("empty", {"username": "", "password": ""}, 400),
        ("oversize_field_1000", {"username": "a"*1000, "password": "p"}, 422),
        ("oversize_body_20000", {"username": "a"*20000, "password": "p"}, 413),
        ("symbols", {"username": "bad!name", "password": "p"}, 422),
        ("nul_char", {"username": "null\x00name", "password": "p"}, 422),
        ("valid", {"username": "user1", "password": "password123"}, 302),
    ]

    for name, data, expected in cases:
        headers = None
        if name == 'valid':
            # Send a different client IP via X-Forwarded-For so rate limiter
            # treats this as a separate client during tests.
            headers = {'X-Forwarded-For': '1.2.3.4'}
            resp = client.post('/login', data=data, headers=headers, follow_redirects=False)
        else:
            resp = client.post('/login', data=data, follow_redirects=False)
        body = resp.get_data(as_text=True)
        snippet = body.strip().replace('\n', ' ')[:200]
        print(f"{name}: status={resp.status_code} expected={expected} snippet={snippet!r}")

if __name__ == '__main__':
    run_tests()

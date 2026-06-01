import pytest

from app import app as flask_app
from database import init_db, seed_db
import database as db_module
from extensions import limiter


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    db_module.DATABASE_PATH = "/tmp/test_8techbank_demo.db"
    try:
        init_db()
        seed_db()
        yield
    finally:
        import os
        if os.path.exists(db_module.DATABASE_PATH):
            os.remove(db_module.DATABASE_PATH)


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        with flask_app.app_context():
            limiter.reset()
        yield c
        with flask_app.app_context():
            limiter.reset()


def test_rate_limiter_blocks_after_five_attempts(client):
    # Five failed auth attempts should be allowed, sixth should be 429
    for i in range(5):
        r = client.post('/api/auth/token', json={"username": "nope", "password": "bad"})
        assert r.status_code in (401, 422)

    r6 = client.post('/api/auth/token', json={"username": "nope", "password": "bad"})
    assert r6.status_code == 429
    body = r6.get_data(as_text=True).lower()
    assert 'too many' in body or 'rate' in body


def test_validator_rejects_invalid_and_negative_transfer(client):
    # Missing fields on auth token → 422 with details
    r = client.post('/api/auth/token', json={"password": "x"})
    assert r.status_code == 422
    assert 'details' in r.get_json()
    assert 'username' in r.get_json()['details']

    # Obtain a valid access token
    r2 = client.post('/api/auth/token', json={"username": "admin", "password": "admin123"})
    assert r2.status_code == 200
    token = r2.get_json()['access_token']

    # Transfer negative amount → 422 and details mention amount
    r3 = client.post('/api/transfer', json={"to_account": "8TB-000002", "amount": -5}, headers={"Authorization": f"Bearer {token}"})
    assert r3.status_code == 422
    assert 'amount' in r3.get_json()['details']

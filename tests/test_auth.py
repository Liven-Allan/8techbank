import pytest
from app import app as flask_app
import time

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    # Ensure limiter is reset between tests if using memory storage
    with flask_app.test_client() as c:
        yield c


def test_token_validation_missing_field(client):
    res = client.post('/api/auth/token', json={'username': 'admin'})
    assert res.status_code in (400, 422)


def test_rate_limit_on_token_endpoint(client):
    # Make 5 failing attempts
    for _ in range(5):
        r = client.post('/api/auth/token', json={'username': 'wrong', 'password': 'bad'})
        # Allow validation errors or early 429 if limiter already reached in this process
        assert r.status_code in (400, 401, 422, 429)
    # 6th attempt should be rate-limited (429)
    r6 = client.post('/api/auth/token', json={'username': 'wrong', 'password': 'bad'})
    assert r6.status_code == 429
 
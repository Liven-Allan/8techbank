import pytest
from app import app as flask_app
from extensions import limiter

import re

@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        with flask_app.app_context():
            limiter.reset()
        yield c
        with flask_app.app_context():
            limiter.reset()


def test_login_empty_fields_returns_400(client):
    r = client.post('/login', data={'username':'', 'password':''})
    assert r.status_code == 400
    assert 'Fields cannot be empty' in r.get_data(as_text=True)


def test_login_oversized_input_returns_422(client):
    long = 'A' * 151
    r = client.post('/login', data={'username': long, 'password': 'p'})
    assert r.status_code == 422
    assert 'Input too large' in r.get_data(as_text=True)


def test_register_empty_fields_returns_400(client):
    r = client.post('/register', data={'username':'', 'email':'', 'password':''})
    assert r.status_code == 400
    assert 'All fields are required' in r.get_data(as_text=True)


def test_register_invalid_email_returns_422(client):
    r = client.post('/register', data={'username':'u', 'email':'@@@@@@', 'password':'p'})
    assert r.status_code == 422
    assert 'Invalid email format' in r.get_data(as_text=True)


def test_register_oversized_input_returns_422(client):
    long = 'A' * 151
    r = client.post('/register', data={'username': long, 'email':'u@example.com', 'password':'p'})
    assert r.status_code == 422
    assert 'Input too large' in r.get_data(as_text=True)

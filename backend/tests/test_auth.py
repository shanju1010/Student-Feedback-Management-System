import os
import tempfile
from pathlib import Path

_db = Path(tempfile.mkdtemp()) / 'test.db'
os.environ['DATABASE_URL'] = f'sqlite:///{_db}'
from fastapi.testclient import TestClient
from app.main import app, SessionLocal, User, password_hash

client = TestClient(app)

def test_health():
    assert client.get('/health').json() == {'status': 'ok'}

def test_authentication_and_roles():
    with SessionLocal() as db:
        db.add(User(email='student@example.edu', password_hash=password_hash.hash('example-password-123'), role='student'))
        db.commit()
    assert client.get('/auth/me').status_code == 401
    assert client.post('/auth/login', json={'email':'student@example.edu','password':'wrong'}).status_code == 401
    r = client.post('/auth/login', json={'email':'student@example.edu','password':'example-password-123'})
    assert r.status_code == 200
    assert 'httponly' in r.headers['set-cookie'].lower()
    assert client.get('/auth/me').json()['role'] == 'student'
    assert client.get('/admin/check').status_code == 403
    assert client.post('/auth/logout').status_code == 200
    assert client.get('/auth/me').status_code == 401

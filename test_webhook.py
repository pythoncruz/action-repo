import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_webhook(client):
    response = client.post('/webhook', json={"test": "payload"})
    assert response.status_code == 403  # Expecting 403 due to missing signature
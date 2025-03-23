from app import app  # Import your Flask app
import pytest

@pytest.fixture
def client():
    # This creates a test client for the Flask app
    with app.test_client() as client:
        yield client

def test_auth(client):
    # Test POST /auth endpoint
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'jwt' in response.json  # Ensure the response contains the 'jwt' field

def test_jwks(client):
    # Test GET /.well-known/jwks.json endpoint
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert 'keys' in response.json  # Ensure the response contains the 'keys' field

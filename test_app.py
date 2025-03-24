from app import app  # Import your Flask app
import pytest
import jwt
import sqlite3
from datetime import datetime, timedelta

# Create a test client
@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

# Test POST /auth endpoint
def test_auth(client):
    # Test POST /auth endpoint to get JWT
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'jwt' in response.json  # Ensure the response contains the 'jwt' field

# Test GET /.well-known/jwks.json endpoint
def test_jwks(client):
    # Test GET /.well-known/jwks.json endpoint
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert 'keys' in response.json  # Ensure the response contains the 'keys' field

# Test GET /protected-endpoint with a valid JWT
def test_protected(client):
    # Get a valid JWT
    token_response = client.post('/auth')
    token = token_response.json['jwt']
    
    # Access protected route with JWT
    response = client.get('/protected-endpoint', headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json['message'] == 'This is a protected route.'

# Test GET /protected-endpoint without a JWT
def test_protected_no_token(client):
    # Test GET /protected-endpoint with no token
    response = client.get('/protected-endpoint')
    assert response.status_code == 403
    assert 'Token is missing!' in response.json['message']

# Test GET /protected-endpoint with an expired JWT
def test_expired_jwt(client):
    # Manually create an expired JWT
    expired_payload = {
        "username": "userABC",
        "password": "password123",
        "exp": datetime.utcnow() - timedelta(days=1)  # Set expiration time to 1 day in the past
    }
    expired_token = jwt.encode(expired_payload, 'your-private-key', algorithm='RS256')
    
    # Access protected route with expired token
    response = client.get('/protected-endpoint', headers={"Authorization": f"Bearer {expired_token}"})
    assert response.status_code == 401
    assert 'Token has expired!' in response.json['message']

# Test case where no keys are available in the database
def test_no_keys(client):
    # Ensure the database is empty before running the test
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM keys')
    conn.commit()
    conn.close()

    # Attempt to authenticate when there are no keys in the database
    response = client.post('/auth')
    assert response.status_code == 404
    assert 'No valid key found' in response.json['error']

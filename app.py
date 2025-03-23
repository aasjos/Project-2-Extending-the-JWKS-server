from flask import Flask, jsonify, request
import jwt
import sqlite3
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from functools import wraps

# Initialize the Flask app
app = Flask(__name__)

# Function to generate and store a private key
def generate_and_store_key(expiration_time):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiration_time))
    conn.commit()
    conn.close()

# Function to retrieve the private key from the database
def get_private_key(expired=False):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    if expired:
        cursor.execute('SELECT key FROM keys WHERE exp < ?', (int(time.time()),))
    else:
        cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(time.time()),))
    
    key_row = cursor.fetchone()
    conn.close()
    
    if key_row:
        return key_row[0]
    else:
        return None

# Function to retrieve the public key
def get_public_key():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(time.time()),))
    key_row = cursor.fetchone()
    conn.close()

    if key_row:
        private_key_pem = key_row[0]
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        # Extract public key from the private key
        public_key = private_key.public_key()
        
        # Serialize the public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_pem
    else:
        return None

# Decorator to protect routes
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check if the token is passed in the Authorization header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Extract token from "Bearer <token>"
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        
        try:
            # Decode the token using the public key (RS256)
            public_key_pem = get_public_key()  # Get the public key
            if public_key_pem is None:
                return jsonify({'message': 'Public key not found!'}), 400
            
            public_key = serialization.load_pem_public_key(public_key_pem)
            decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        return f(*args, **kwargs)

    return decorated_function

# Endpoint to authenticate and issue JWT
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired') == 'true'
    private_key_pem = get_private_key(expired)
    
    if private_key_pem is None:
        return jsonify({"error": "No valid key found"}), 404
    
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    payload = {"username": "userABC", "password": "password123"}
    token = jwt.encode(payload, private_key, algorithm="RS256")
    
    return jsonify({"jwt": token})

# Endpoint to retrieve public keys (JWKS format)
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (int(time.time()),))
    keys = cursor.fetchall()
    conn.close()

    jwks = {"keys": []}
    
    for key_row in keys:
        private_key_pem = key_row[0]
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        jwks["keys"].append({
            "kid": "unique-key-id",  # You should generate a unique kid for each key
            "kty": "RSA",
            "n": public_pem.decode().split("\n")[1],  # Extract public key (modulus 'n')
            "e": "AQAB"  # Public exponent (always "AQAB" for RSA keys)
        })

    return jsonify(jwks)

# Protected route: This requires a valid JWT to access
@app.route('/protected-endpoint', methods=['GET'])
@token_required  # This line ensures that the JWT is verified before accessing this route
def protected():
    return jsonify({'message': 'This is a protected route.'})

if __name__ == '__main__':
    app.run(debug=True)

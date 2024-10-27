from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
import time
import uuid
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import json
import os

# Database setup
DATABASE = "totally_not_my_privateKeys.db"

def init_db():
    """Initialize the SQLite database and create the 'keys' table if it doesn't exist."""
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            kid TEXT PRIMARY KEY,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
        """)
        conn.commit()
        conn.close()
        print("Database initialized.")
    else:
        print("Database already exists.")

def generate_and_store_key(expired=False):
    """Generate an RSA private key, store it in the database, and return its metadata."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    
    # Serialize private key in PKCS1 PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    kid = str(uuid.uuid4())
    expiry = int(time.time()) + 3600 if not expired else int(time.time()) - 3600

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)", (kid, private_pem, expiry))
    conn.commit()
    conn.close()

    print(f"Generated key with kid: {kid}, expiry: {expiry}, expired: {expired}")  # Debugging line

    return kid, private_key, expiry

# Initialize the database and generate initial keys
  # Generate a valid key


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/.well-known/jwks.json":
            # Retrieve all non-expired keys from the database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (int(time.time()),))
            rows = cursor.fetchall()
            conn.close()

            valid_keys = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": row[0],
                        "use": "sig",
                        "n": serialization.load_pem_public_key(row[1].encode("utf-8"), backend=default_backend()).public_bytes(
                            encoding=serialization.Encoding.Raw,  # Change to Raw to get the base64
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ).decode("utf-8"),
                        "e": "AQAB",  # Assuming the exponent is fixed
                        "exp": row[2],
                    }
                    for row in rows
                ]
            }

            print(f"JWKS Response: {json.dumps(valid_keys, indent=2)}")  # Debugging line

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(valid_keys).encode("utf-8"))

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                bytes("<html><body><h1>404 Not Found</h1></body></html>", "utf-8")
            )

    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/auth":
            # Parse the "expired" query parameter
            query = parse_qs(parsed_path.query)
            expired = query.get("expired", ["false"])[0].lower() == "true"

            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            if expired:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp < ? LIMIT 1", (int(time.time()),))
            else:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (int(time.time()),))

            row = cursor.fetchone()
            conn.close()

            if row:
                kid, private_pem, expiry = row
                private_key = serialization.load_pem_private_key(
                    private_pem.encode("utf-8"),
                    password=None,
                    backend=default_backend()
                )

                # Create JWT
                token = jwt.encode(
                    {"exp": expiry},
                    private_key,
                    algorithm="RS256",
                    headers={"kid": kid}
                )

                print(f"Generated JWT: {token} with kid: {kid}")  # Debugging line

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"token": token}).encode("utf-8"))
            else:
                self.send_response(404)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No appropriate key found"}).encode("utf-8"))

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                bytes("<html><body><h1>404 Not Found</h1></body></html>", "utf-8")
            )

hostName = "localhost"
serverPort = 8080

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started at http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

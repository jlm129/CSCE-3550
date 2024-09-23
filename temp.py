from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import uuid
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import json
#could not get it to run on port 8080 for some reason and as such could not get the test software to run
keys = {}


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Generate key ID and expiry timestamp
    kid = str(uuid.uuid4())
    expiry = int(time.time()) + 3600  # 1 hour expiry

    keys[kid] = {"private_key": private_key, "public_key": public_pem, "expiry": expiry}
    return kid, public_pem.decode("utf-8"), expiry


current_kid, current_public_key, current_expiry = generate_key()


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            valid_keys = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": current_kid,
                        "use": "sig",
                        "n": current_public_key,
                        "e": "AQAB",
                        "exp": current_expiry,
                    }
                ]
            }
            self.wfile.write(json.dumps(valid_keys).encode("utf-8"))

        elif parsed_path.path == "/auth":
            # Handling the auth endpoint
            query = parse_qs(parsed_path.query)
            expired = query.get("expired", ["false"])[0].lower() == "true"

            if not expired:
                key = keys[current_kid]["private_key"]
                expiry = int(time.time()) + 3600  # 1 hour expiry
            else:
                key = keys[current_kid]["private_key"]
                expiry = int(time.time()) - 3600  # 1 hour in the past

            # Create JWT
            token = jwt.encode(
                {"exp": expiry}, key, algorithm="RS256", headers={"kid": current_kid}
            )

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode("utf-8"))

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                bytes("<html><body><h1>404 Not Found</h1></body></html>", "utf-8")
            )


hostName = "localhost"
serverPort = 8081

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started at http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

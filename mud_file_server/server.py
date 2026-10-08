from flask import Flask, send_from_directory, jsonify, make_response
import os
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)
MUD_FILES_DIR = os.path.join(os.path.dirname(__file__), '..', 'mud_files')
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), '..', 'mud_private_key.pem')

# Load the RSA private key ONCE at server startup.
# In real RFC 8520 deployments, this key belongs only to the
# manufacturer and is used to sign every MUD file they publish.
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)


def sign_data(data_bytes):
    """
    Signs the given bytes using RSA-2048 + SHA-256 (PSS padding).
    Unlike HMAC, only the holder of the PRIVATE key can produce a
    valid signature. The manager (client) will verify this using
    only the PUBLIC key, and can never forge a new signature itself.
    """
    signature = PRIVATE_KEY.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Convert raw signature bytes to a hex string for the HTTP header
    return signature.hex()


@app.route('/mud/<filename>')
def serve_mud_file(filename):
    """Serve MUD JSON files with a digital signature header — simulates
    the manufacturer's server signing the file before releasing it."""
    try:
        file_path = os.path.join(MUD_FILES_DIR, filename)
        with open(file_path, 'rb') as f:
            file_bytes = f.read()

        signature = sign_data(file_bytes)

        response = make_response(file_bytes)
        response.headers['Content-Type'] = 'application/mud+json'
        response.headers['X-MUD-Signature'] = signature
        return response

    except FileNotFoundError:
        return jsonify({"error": "MUD file not found"}), 404


@app.route('/')
def index():
    files = os.listdir(MUD_FILES_DIR)
    return jsonify({"available_mud_files": files,
                    "server_info": "MUD File Server - RFC 8520 (Signed)"})


if __name__ == '__main__':
    print("[MUD FILE SERVER] Starting on http://localhost:5000")
    print("[MUD FILE SERVER] MUD files available at: http://localhost:5000/mud/<filename>")
    print("[MUD FILE SERVER] All files are signed with RSA-2048 (PSS, SHA-256)")
    app.run(host='0.0.0.0', port=5000, debug=False)

# e2ee_api_simulation.py
# Single-file Flask server + client demo that simulates E2EE messaging.
# Usage:
#   python e2ee_api_simulation.py        # starts server
#   python e2ee_api_simulation.py demo   # starts server and runs demo (Alice->Bob)

import os
import base64
import json
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request
import requests

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# ------------- In-memory "server" storage (keeps only encrypted envelopes) -------------
DB = {
    "users": {},     # userId -> {userId, public_key_pem}
    "messages": []   # list of envelopes: {from, to, payload, received_at}
}

# ------------- Flask app (server) -------------
app = Flask(__name__)

def json_response(payload, status=200):
    return jsonify(payload), status

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    user_id = data.get("userId")
    public_key_pem = data.get("publicKeyPem")
    if not user_id or not public_key_pem:
        return json_response({"success": False, "error": "userId and publicKeyPem required"}, 400)
    DB["users"][user_id] = {"userId": user_id, "publicKeyPem": public_key_pem}
    return json_response({"success": True, "message": f"{user_id} registered"})

@app.route("/send", methods=["POST"])
def send_envelope():
    data = request.get_json(force=True)
    frm = data.get("from")
    to = data.get("to")
    payload = data.get("payload")
    if not frm or not to or not payload:
        return json_response({"success": False, "error": "from, to, payload required"}, 400)
    if frm not in DB["users"] or to not in DB["users"]:
        return json_response({"success": False, "error": "sender or recipient not registered"}, 404)
    envelope = {
        "from": frm,
        "to": to,
        "payload": payload,
        "receivedAt": datetime.utcnow().isoformat() + "Z"
    }
    DB["messages"].append(envelope)
    return json_response({"success": True, "message": "Message securely stored"})

@app.route("/messages/<user_id>", methods=["GET"])
def get_messages(user_id):
    if user_id not in DB["users"]:
        return json_response({"success": False, "error": "user not registered"}, 404)
    inbox = [m for m in DB["messages"] if m["to"] == user_id]
    return json_response({"success": True, "messages": inbox})

@app.route("/status", methods=["GET"])
def status():
    return json_response({
        "success": True,
        "message": "server running",
        "users": list(DB["users"].keys()),
        "totalMessages": len(DB["messages"])
    })


# ------------- Client-side cryptography helpers (these simulate client behavior) -------------

def generate_rsa_keypair():
    """
    Generates 2048-bit RSA keypair and returns (public_pem_str, private_pem_str)
    Private key is PEM-encoded PKCS8, public key is PEM-encoded SPKI.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub_pem.decode("utf-8"), priv_pem.decode("utf-8"), private_key

def rsa_encrypt_oaep(plaintext_bytes, public_key_pem_str):
    pub = serialization.load_pem_public_key(public_key_pem_str.encode("utf-8"))
    ct = pub.encrypt(
        plaintext_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(ct).decode("utf-8")

def rsa_decrypt_oaep(base64_ciphertext, private_key):
    ct = base64.b64decode(base64_ciphertext)
    pt = private_key.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return pt  # bytes

def aes_gcm_encrypt(plaintext_str, key_bytes):
    aesgcm = AESGCM(key_bytes)
    iv = os.urandom(12)  # 12-byte random nonce
    ct = aesgcm.encrypt(iv, plaintext_str.encode("utf-8"), None)
    tag = ct[-16:]
    ciphertext = ct[:-16]
    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "authTag": base64.b64encode(tag).decode("utf-8")
    }


def aes_gcm_decrypt(payload, key_bytes):
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    authTag = base64.b64decode(payload["authTag"])
    ct_with_tag = ciphertext + authTag
    aesgcm = AESGCM(key_bytes)
    pt = aesgcm.decrypt(iv, ct_with_tag, None)
    return pt.decode("utf-8")

# ------------- Client actions using requests to interact with server -------------

def client_register(server_url, user_id, public_key_pem):
    r = requests.post(f"{server_url}/register", json={"userId": user_id, "publicKeyPem": public_key_pem})
    return r.json()

def client_send_encrypted(server_url, frm, to, plaintext, recipient_public_pem):
    # 1) Generate AES-256 key
    aes_key = AESGCM.generate_key(bit_length=256)  # returns bytes (32)
    # 2) Encrypt plaintext with AES-GCM
    enc = aes_gcm_encrypt(plaintext, aes_key)  # iv, ciphertext, authTag (base64)
    # 3) Encrypt AES key with recipient RSA public key (OAEP)
    encrypted_key_b64 = rsa_encrypt_oaep(aes_key, recipient_public_pem)
    payload = {
        "encryptedKey": encrypted_key_b64,
        "iv": enc["iv"],
        "ciphertext": enc["ciphertext"],
        "authTag": enc["authTag"]
    }
    r = requests.post(f"{server_url}/send", json={"from": frm, "to": to, "payload": payload})
    return r.json()

def client_fetch_messages(server_url, user_id):
    r = requests.get(f"{server_url}/messages/{user_id}")
    return r.json()

def client_decrypt_envelope(envelope, recipient_private_key_obj):
    payload = envelope["payload"]
    # decrypt AES key
    aes_key = rsa_decrypt_oaep(payload["encryptedKey"], recipient_private_key_obj)  # bytes
    # decrypt message
    plaintext = aes_gcm_decrypt(payload, aes_key)
    return plaintext

# ------------- Demo flow (Alice -> Bob) -------------

def run_demo_flow(server_url):
    print("\n📱 Demo: Alice sends Bob a secret message (E2EE simulation)\n")

    # Create keypairs for Alice and Bob (private keys remain local)
    alice_pub_pem, alice_priv_pem, alice_priv_obj = generate_rsa_keypair()
    bob_pub_pem, bob_priv_pem, bob_priv_obj = generate_rsa_keypair()
    print("🔐 Generated RSA keypairs for Alice and Bob (private keys are local only).")

    # Register public keys with server
    r1 = client_register(server_url, "alice", alice_pub_pem)
    r2 = client_register(server_url, "bob", bob_pub_pem)
    print("👤 Registration results:", r1, r2)

    # Alice sends encrypted message to Bob
    secret_message = "Hey Bob 👋, this message is end-to-end encrypted."
    send_res = client_send_encrypted(server_url, "alice", "bob", secret_message, bob_pub_pem)
    print("📤 Alice sent a message result:", send_res)

    # Bob fetches messages (server returns encrypted envelopes)
    inbox = client_fetch_messages(server_url, "bob")
    print("\n📥 Bob's inbox (encrypted envelopes returned by server):")
    print(json.dumps(inbox, indent=2))

    # Bob decrypts messages locally using his private key object
    if inbox.get("success") and inbox.get("messages"):
        for env in inbox["messages"]:
            try:
                pt = client_decrypt_envelope(env, bob_priv_obj)
                print("\n🔓 Decrypted message from", env["from"] + ":", pt)
            except Exception as e:
                print("❌ Failed to decrypt:", str(e))
    else:
        print("No messages to decrypt.")

    print("\n✅ Demo complete — server only stored encrypted data.")


# ------------- Boot server and optionally run demo -------------
def start_server_in_thread():
    # Flask debug False for predictable output; threaded True to serve multiple requests
    server_thread = threading.Thread(target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, threaded=True), daemon=True)
    server_thread.start()
    # small wait to allow server to bind
    time.sleep(0.4)
    return server_thread

if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    # If 'demo' passed, start server and run demo in same process
    if args and args[0].lower() == "demo":
        start_server_in_thread()
        try:
            run_demo_flow("http://127.0.0.1:5000")
            print("\nServer still running at http://127.0.0.1:5000 (press Ctrl+C to stop)\n")
            # keep main thread alive so server keeps running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down.")
            sys.exit(0)
    else:
        # Start server only (foreground)
        print("Starting server at http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=5000, debug=False)

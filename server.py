from flask import Flask, request, jsonify
import threading
from collections import defaultdict

from flask import Flask, request, jsonify
import threading
from collections import defaultdict

app = Flask(__name__)

# Store public keys and encrypted messages
PUBLIC_KEYS = {}
MESSAGES = defaultdict(list)
lock = threading.Lock()

@app.route("/register", methods=["POST"])
def register():
    """Register a user with their public key"""
    data = request.get_json()
    if not data or "username" not in data or "public_key" not in data:
        return jsonify({"status": "error", "message": "username and public_key required"}), 400
    username = data["username"]
    public_key = data["public_key"]
    with lock:
        PUBLIC_KEYS[username] = public_key
    return jsonify({"status": "success", "message": f"{username} registered successfully"})

@app.route("/get_public_key/<username>", methods=["GET"])
def get_public_key(username):
    """Return a user's public key"""
    with lock:
        key = PUBLIC_KEYS.get(username)
    if not key:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "public_key": key})

@app.route("/send_message", methods=["POST"])
def send_message():
    """Store an encrypted message"""
    data = request.get_json()
    required = {"sender", "receiver", "encrypted_message"}
    if not data or not required.issubset(data.keys()):
        return jsonify({"status": "error", "message": "sender, receiver, encrypted_message required"}), 400
    with lock:
        MESSAGES[data["receiver"]].append({
            "from": data["sender"],
            "message": data["encrypted_message"]
        })
    return jsonify({"status": "success", "message": "Encrypted message sent!"})

@app.route("/receive_messages/<username>", methods=["GET"])
def receive_messages(username):
    """Return encrypted messages for a user"""
    with lock:
        user_msgs = MESSAGES.get(username, [])
        MESSAGES[username] = []  # clear inbox
    return jsonify({"status": "success", "messages": user_msgs})

if __name__ == "__main__":
    app.run(debug=True)

import requests
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_URL = "http://127.0.0.1:5000"

def generate_keys(username):
    """Generate RSA keys for a user"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save keys to files
    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"[+] Keys generated for {username}")

    return private_key, public_key

def register(username):
    """Register user and send public key to server"""
    with open(f"{username}_public.pem", "rb") as f:
        pub_key = f.read()
    pub_key_b64 = base64.b64encode(pub_key).decode("utf-8")
    res = requests.post(f"{SERVER_URL}/register", json={
        "username": username,
        "public_key": pub_key_b64
    })
    print(res.json())

def get_public_key(username):
    """Get another user's public key"""
    res = requests.get(f"{SERVER_URL}/get_public_key/{username}")
    data = res.json()
    if data["status"] == "success":
        return base64.b64decode(data["public_key"])
    else:
        print(data)
        return None

def encrypt_message(public_key_bytes, message):
    """Encrypt message using recipient’s public key"""
    public_key = serialization.load_pem_public_key(public_key_bytes)
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_message(username, encrypted_message_b64):
    """Decrypt message using your private key"""
    with open(f"{username}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    encrypted_bytes = base64.b64decode(encrypted_message_b64)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def send_message(sender, receiver, message):
    """Encrypt and send a message"""
    receiver_pub_key = get_public_key(receiver)
    encrypted_msg = encrypt_message(receiver_pub_key, message)
    res = requests.post(f"{SERVER_URL}/send_message", json={
        "sender": sender,
        "receiver": receiver,
        "encrypted_message": encrypted_msg
    })
    print(res.json())

def receive_messages(username):
    """Receive encrypted messages and decrypt them"""
    res = requests.get(f"{SERVER_URL}/receive_messages/{username}")
    data = res.json()
    if data["status"] == "success":
        for msg in data["messages"]:
            decrypted = decrypt_message(username, msg["message"])
            print(f"From {msg['from']}: {decrypted}")
    else:
        print(data)

# Example usage
if __name__ == "__main__":
    print("1. Generate keys and register users first:")
    print("   generate_keys('alice'); register('alice')")
    print("   generate_keys('bob'); register('bob')")
    print("2. Then run:")
    print("   send_message('alice','bob','Hello Bob!')")
    print("   receive_messages('bob')")

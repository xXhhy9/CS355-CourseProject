import socket
import hashlib
import base64
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Function to generate a private key using Elliptic Curve Cryptography
def generate_private_key():
    return ec.generate_private_key(ec.SECP384R1())

# Function to serialize the public key to PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Derives a symmetric key using HMAC-based Key Derivation Function (HKDF)
def derive_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)

def generate_hmac(key, message):
    # Create a new HMAC object using the SHA-256 hash algorithm and the key
    hmac_obj = hmac.new(key, message.encode(), hashlib.sha256)
    # Generate HMAC
    hmac_digest = hmac_obj.digest()
    # Return the base64 encoded HMAC
    return base64.b64encode(hmac_digest).decode()

def verify_hmac(key, message, hmac_to_verify):
    # Generate the HMAC for the message
    generated_hmac = generate_hmac(key, message)
    # Compare the generated HMAC with the provided HMAC
    return generated_hmac == hmac_to_verify

def compute_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        buffer = file.read(8192)
        while buffer:
            hasher.update(buffer)
            buffer = file.read(8192)
    return base64.b64encode(hasher.digest()).decode()

def main():
    HOST = 'localhost'
    PORT = 8080

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening on {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            private_key = generate_private_key()

            alice_public_key = serialization.load_pem_public_key(conn.recv(1024))
            conn.sendall(serialize_public_key(private_key.public_key()))

            shared_secret = private_key.exchange(ec.ECDH(), alice_public_key)
            secret_key = derive_key(shared_secret)

            bob_hash = compute_hash('segment.bin')
            bob_mac = generate_hmac(secret_key, bob_hash)
            conn.sendall(f"{bob_hash},{bob_mac}".encode())

            data = conn.recv(1024).decode()
            alice_hash, alice_mac = data.split(',')

            if verify_hmac(secret_key, alice_hash, alice_mac):
                print("HMAC verified")
            else:
                print("HMAC verification failed")           

            # print(f"Alice's Hash: {alice_hash}")
            # print(f"Bob's Hash: {bob_hash}")

            if (bob_hash == alice_hash):
                print("Same Code Segment")
            else:
                print("Different Code Segment")

if __name__ == "__main__":
    main()

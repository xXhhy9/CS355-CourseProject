import sys
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
    #checking for the required number of segments
    if (len(sys.argv) < 6):
        print("error, less than the required 5 segments has been provied")
        return

    HOST = 'localhost'
    PORT = 8080

    #creating the socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, PORT))
            s.listen()
        except:
            print("error on socket creation")
            return

        print(f"Listening on {HOST}:{PORT}")
        try:
            conn, addr = s.accept()
        except:
            s.close()
            print("error accepting new connection")
            return
        with conn:
            print(f"Connected by {addr}")

            #Stage 1: Key exchange. Alice and Bob use each other's public keys and their own private keys
            # to compute the shared key.
            private_key = generate_private_key()
            alice_public_key = serialization.load_pem_public_key(conn.recv(1024))
            conn.sendall(serialize_public_key(private_key.public_key()))

            # Bob generates a value using his private key and Alice's public key, while Alice generates a value using her private key and Bob's public key.
            # Due to the property of ECDH, these two values are shared secret
            # Secret_key will be used for HMAC
            shared_secret = private_key.exchange(ec.ECDH(), alice_public_key)
            secret_key = derive_key(shared_secret)

            # Stage 2: File Hashing & Mac Generation. Alice and Bob calculate the hash of their file separately.
            bob_hashes = []
            bob_macs = []
            output_str = ""
            for i in range (1,5):
                try:
                    bob_hashes[i-1] = compute_hash(sys.argv[i])
                except FileNotFoundError:
                    print(f"No file with the name {sys.argv[i]} found.")
                    s.close()
                    return
                bob_macs[i-1] = generate_hmac(secret_key, bob_hashes[i])
                output_str += f";{bob_hashes[i-1]},{bob_macs[i-1]}"
            #bob_hash = compute_hash('segment.bin')
            #bob_mac = generate_hmac(secret_key, bob_hash)

            # Stage 3: Exchanging hashes with Alice.
            print("Sending hashes and HMAC's to Alice.")
            conn.sendall(output_str.encode())

            data = conn.recv(1024).decode()
            alice_outs = []
            alice_outs[0:4] = data.split(';')
            alice_hashes = []
            alice_macs = []
            for i in range (0,4):
                alice_hashes[i], alice_macs[i] = alice_outs[i].split(',')
            #alice_hash, alice_mac = data.split(',')

            # Verification and Hash Comparison
            for i in range (0,4):
                if not verify_hmac(secret_key, bob_hashes[i], bob_macs[i]):
                    raise Exception(f"Failed to verify Bob mac #{i+1}.")
            print("Verification successful")  

            # print(f"Alice's Hash: {alice_hash}")
            # print(f"Bob's Hash: {bob_hash}")

        for i in range (0,4):
            for j in range (0,4):
                if (bob_hashes[i] == alice_hashes[j]):
                    print(f"Bob segment #{i+1} matches with Alice segment #{j+1}.")
                else:
                    print(f"Bob segment #{i+1} does not match with ALice segment #{j+1}.")

if __name__ == "__main__":
    main()

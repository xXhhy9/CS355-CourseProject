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
# Reference: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman
def generate_private_key():
    return ec.generate_private_key(ec.SECP384R1())

# Function to serialize the public key to PEM format
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Derives a symmetric key using HMAC-based Key Derivation Function (HKDF)
# HMAC is effective against length extension attacks
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
    print("Verifying HMAC.")
    # Generate the HMAC for the message
    generated_hmac = generate_hmac(key, message)
    # Compare the generated HMAC with the provided HMAC
    return generated_hmac == hmac_to_verify

# Computes SHA-256 hash of a file
def compute_hash(file_path):
    print(f"Computing hash for {file_path}.")
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        buffer = file.read(8192)
        while buffer:
            hasher.update(buffer)
            buffer = file.read(8192)
    return base64.b64encode(hasher.digest()).decode()

def main():
    #make sure all file names are included.
    if (len(sys.argv) < 6):
            print("Please input the correct number of filenames to send to Bob.")
            return

    HOST = 'localhost'
    PORT = 8080

    # Alice generates her public key and private key
    private_key = generate_private_key()
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to {HOST}:{PORT}.")
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("Failed to connect to Bob")
            return

        # Stage 1: Key exchange. Alice and Bob use each other's public keys and their own private keys
        # to compute the shared key.
        s.sendall(serialize_public_key(public_key))   
        bob_public_key = serialization.load_pem_public_key(s.recv(1024))
        
        # Alice generates a value using her private key and Bob's public key, while Bob generates a value using his private key and Alice's public key.
        # Due to the property of ECDH, these two values are shared secret
        shared_secret = private_key.exchange(ec.ECDH(), bob_public_key)
        
        # Secret_key will be used for HMAC
        secret_key = derive_key(shared_secret)

        # Stage 2: File Hashing & Mac Generation. Alice and Bob calculate the hash of their file separately.
        alice_hashes = []
        alice_macs = []
        output_str = ""
        for i in range (1,5):
            try:
                alice_hashes[i-1] = compute_hash(sys.argv[i])
            except FileNotFoundError:
                print(f"No file with the name {sys.argv[i]} found.")
                s.close()
                return

            alice_macs[i-1] = generate_hmac(secret_key, alice_hashes[i])
            output_str += f";{alice_hashes[i-1]},{alice_macs[i-1]}"
        #alice_hash = compute_hash('segment.bin')
        #print(f"File hash: {alice_hash}")

        # Stage 3: Exchanging hashes with Bob.
        print(f"Sending hashes and HMAC's to Bob.")
        s.sendall(output_str.encode())

        # Stage 4: Exchange MAC and hash
        data = s.recv(1024).decode()
        
        bob_outs = []
        bob_outs[0:4] = data.split(';')
        bob_hashes = []
        bob_macs = []
        for i in range (0,4):
            bob_hashes[i], bob_macs[i] = bob_outs[i].split(',')

        # Verification and Hash Comparison
        for i in range (0,4):
            if not verify_hmac(secret_key, bob_hashes[i], bob_macs[i]):
                raise Exception(f"Failed to verify Bob mac #{i+1}.")
        print("Verification successful")
    
        for i in range (0,4):
            for j in range (0,4):
                if (alice_hashes[i] == bob_hashes[j]):
                    print(f"Alice segment #{i+1} matches with Bob segment #{j+1}.")
                else:
                    print(f"Alice segment #{i+1} does not match with Bob segment #{j+1}.")

if __name__ == "__main__":
    main()

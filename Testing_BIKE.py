import oqs
import os
import base64
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_shared_secret(shared_secret, salt, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(shared_secret)

def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_data

kem_algorithm = "BIKE-L3"
with oqs.KeyEncapsulation(kem_algorithm) as client:
    # Time BIKE Key Generation
    start_time = time.time()
    public_key = client.generate_keypair()
    private_key = client.export_secret_key()
    key_gen_time = time.time() - start_time
    print(f"BIKE Key Generation Time: {key_gen_time:.6f} seconds")

    with oqs.KeyEncapsulation(kem_algorithm) as server:
        ciphertext, shared_secret_server = server.encap_secret(public_key)
        print(f"Ciphertext Length: {len(ciphertext)} bytes")

    shared_secret_client = client.decap_secret(ciphertext)

    assert shared_secret_server == shared_secret_client, "Decapsulation failed."

    salt = os.urandom(16)
    aes_key = derive_key_from_shared_secret(shared_secret_client, salt)

    original_message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis quis magna lacinia, semper neque vel, suscipit augue. Mauris sagittis maximus molestie."

    # Time AES Encryption
    start_time = time.time()
    encrypted_message = aes_encrypt(original_message, aes_key)
    encryption_time = time.time() - start_time
    print(f"AES Encryption Time: {encryption_time:.6f} seconds")
    print(f"Encrypted Message Length: {len(encrypted_message)} bytes")

    # Time AES Decryption
    start_time = time.time()
    decrypted_message = aes_decrypt(encrypted_message, aes_key)
    decryption_time = time.time() - start_time
    print(f"AES Decryption Time: {decryption_time:.6f} seconds")

    assert original_message == decrypted_message, "Decryption failed."
    print("Original message:", original_message)
    print("Encrypted message (Base64):", base64.b64encode(encrypted_message))
    print("Decrypted message:", decrypted_message)
    print("BIKE key encapsulation, encryption, and decryption successful.")
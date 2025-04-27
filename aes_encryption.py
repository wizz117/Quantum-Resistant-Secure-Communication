from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom

def aes_encrypt(plaintext_bytes, key):
    key = key[:16]  # Ensure key is exactly 16 bytes, AES-128
    iv = urandom(12)  # 12 bytes is recommended for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return iv, encryptor.tag, encrypted_message

def aes_decrypt(iv, tag, encrypted_message, key):
    key = key[:16]  # Ensure key is exactly 16 bytes, AES-128
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message

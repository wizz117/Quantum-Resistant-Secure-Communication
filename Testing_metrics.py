import numpy as np
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from LDPC import LDPC
from McEliece import McEliece

def aes_encrypt(message, key):
    iv = np.random.bytes(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()  
    padded_message = padder.update(message) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv, encrypted_message  

def aes_decrypt(iv, encrypted_message, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_message

n = 3936
d_v = 3
d_c = 6
ldpc = LDPC.from_params(n, d_v, d_c)
crypto = McEliece.from_linear_code(ldpc, 12)

plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis quis magna lacinia, semper neque vel, suscipit augue. Mauris sagittis maximus molestie."
plaintext_bytes = plaintext.encode("utf-8")  # Convert to bytes

start_time = time.time()
binary_word = np.random.randint(2, size=ldpc.getG().shape[0])
encrypted = crypto.encrypt(binary_word)
decrypted = crypto.decrypt(encrypted)
key_gen_time = time.time() - start_time
print(f"McEliece Key Generation and Processing Time: {key_gen_time:.6f} seconds")

aes_key = bytes(decrypted)[:16] 

start_encryption_time = time.time()
iv, encrypted_message = aes_encrypt(plaintext_bytes, aes_key)
encryption_time = time.time() - start_encryption_time
print(f"Encryption Time: {encryption_time:.6f} seconds")
print(f"Ciphertext Length: {len(iv + encrypted_message)} bytes")

start_decryption_time = time.time()
decrypted_message = aes_decrypt(iv, encrypted_message, aes_key)
decryption_time = time.time() - start_decryption_time
print(f"Decryption Time: {decryption_time:.6f} seconds")

decrypted_text = decrypted_message.decode("utf-8")
print("\nOriginal text:", plaintext)
print("\nDecrypted text:", decrypted_text)

assert plaintext == decrypted_text, "Decryption failed"
print("Encryption and decryption with AES successful.")
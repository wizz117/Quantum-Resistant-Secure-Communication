"""
from aes_encryption import aes_encrypt, aes_decrypt

def main():
    key = b'16_byte_key_here_'
    plaintext = "doosuuuu dramebaz"
    tag, encrypted_message = aes_encrypt(plaintext.encode(), key)
    print(f"Encrypted Message: {encrypted_message}")

    decrypted_message = aes_decrypt(encrypted_message, key, tag)
    print(f"Decrypted Message: {decrypted_message.decode()}")

if __name__ == "__main__":
    main()
"""
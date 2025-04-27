import unittest
from aes_encryption import aes_encrypt, aes_decrypt
import os
from hashlib import sha256

class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(16)  # Generate a random key for AES-128

    def test_encryption_decryption(self):
        """Test the basic encryption and decryption functionality."""
        print("\nRunning Test: Encryption and Decryption")
        message = "Test message for encryption"
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        decrypted_message = aes_decrypt(iv, tag, encrypted_message, self.key)
        self.assertEqual(message, decrypted_message.decode(), "The decrypted message should match the original.")
        print("Success: The message was encrypted and decrypted correctly.")

    def test_decryption_with_wrong_key(self):
        """Test decryption using an incorrect key."""
        print("\nRunning Test: Decryption with Wrong Key")
        wrong_key = os.urandom(16)  # Generate a different random key
        message = "Test message for encryption"
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        with self.assertRaises(Exception):
            aes_decrypt(iv, tag, encrypted_message, wrong_key)
        print("Success: Decryption with the wrong key failed as expected.")

    def test_tampered_ciphertext(self):
        """Test the system's response to tampered ciphertext."""
        print("\nRunning Test: Integrity Check Against Tampered Ciphertext")
        message = "Test message for encryption"
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        # Tamper with the encrypted message
        tampered_message = encrypted_message[:-1] + (encrypted_message[-1] ^ 0x01).to_bytes(1, 'little')
        with self.assertRaises(Exception):
            aes_decrypt(iv, tag, tampered_message, self.key)
        print("Success: Tampered ciphertext was detected and decryption failed.")

class TestServerReplayAttack(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(16)
        self.message_history = set()  # Simulate server's message history

    def simulate_server_reception(self, encrypted_message, iv, tag):
        """Simulate server logic for detecting replay attacks."""
        message_hash = sha256(encrypted_message).hexdigest()
        if message_hash in self.message_history:
            raise Exception("Replay attack detected and message discarded.")
        self.message_history.add(message_hash)
        return aes_decrypt(iv, tag, encrypted_message, self.key)

    def test_replay_attack(self):
        """Test the server's ability to detect and reject replayed messages."""
        print("\nRunning Test: Replay Attack Detection")
        message = "Test message susceptible to replay"
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)

        # First receipt should succeed
        decrypted_message = self.simulate_server_reception(encrypted_message, iv, tag)
        self.assertEqual(decrypted_message.decode(), message)

        # Attempt to 'replay' the same message
        with self.assertRaises(Exception) as context:
            self.simulate_server_reception(encrypted_message, iv, tag)
        self.assertIn("Replay attack detected", str(context.exception))
        print("Success: Replay attack was detected and handled correctly.")

if __name__ == '__main__':
    unittest.main()







"""
import unittest
from aes_encryption import aes_encrypt, aes_decrypt
import os

class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(16)  # Correct key for AES-128
        self.wrong_key = os.urandom(16)  # Incorrect key

    def test_encryption_decryption(self):
        message = "Test message for encryption"
        print("\nRunning Test: Encryption and Decryption")
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        decrypted_message = aes_decrypt(iv, tag, encrypted_message, self.key)
        self.assertEqual(message, decrypted_message.decode(), "The decrypted message should match the original.")
        print("Success: The message was encrypted and decrypted correctly.")

    def test_decryption_with_wrong_key(self):
        message = "Test message for encryption"
        print("\nRunning Test: Decryption with Wrong Key")
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        with self.assertRaises(Exception, msg="Decryption should fail with a wrong key."):
            aes_decrypt(iv, tag, encrypted_message, self.wrong_key)
        print("Success: Decryption with the wrong key failed as expected.")

    def test_tampered_ciphertext(self):
        message = "Test message for encryption"
        print("\nRunning Test: Integrity Check Against Tampered Ciphertext")
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)
        # Tamper with the encrypted message
        tampered_message = encrypted_message[:-1] + (encrypted_message[-1] ^ 0x01).to_bytes(1, 'little')
        with self.assertRaises(Exception, msg="Decryption should fail if the ciphertext is tampered with."):
            aes_decrypt(iv, tag, tampered_message, self.key)
        print("Success: Tampered ciphertext was detected and decryption failed.")

    # Add to encryption_tests.py
    def test_replay_attack(self):
        message = "Test message susceptible to replay"
        iv, tag, encrypted_message = aes_encrypt(message.encode(), self.key)

        # First send should be accepted
        first_attempt = aes_decrypt(iv, tag, encrypted_message, self.key)
        self.assertEqual(first_attempt.decode(), message, "First message should be accepted.")

        # Replay the same message
        with self.assertRaises(Exception, msg="Replay attack should be detected and message discarded."):
            aes_decrypt(iv, tag, encrypted_message, self.key)


if __name__ == '__main__':
    unittest.main()
"""
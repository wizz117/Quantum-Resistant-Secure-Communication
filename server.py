import socket
from aes_encryption import aes_encrypt, aes_decrypt
import hashlib

def server_respond(key):
    host, port = '127.0.0.1', 65432
    message_history = set()  # Set to store message hashes to detect replays

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print("Server is listening...")
        conn, addr = s.accept()
        with conn:
            while True:
                try:
                    full_message = conn.recv(1024)
                    if not full_message:
                        break
                    iv = full_message[:12]
                    tag = full_message[12:28]
                    encrypted_message = full_message[28:]
                    
                    # Hash the encrypted message to check for replays
                    message_hash = hashlib.sha256(encrypted_message).hexdigest()
                    if message_hash in message_history:
                        print("Replay attack detected, message discarded.")
                        continue
                    
                    message_history.add(message_hash)
                    message = aes_decrypt(iv, tag, encrypted_message, key)
                    print("Received message:", message.decode())

                    response = "Bike:  Hello from server in response to your message: " + message.decode()
                    iv, tag, encrypted_response = aes_encrypt(response.encode(), key)
                    conn.sendall(iv + tag + encrypted_response)
                except Exception as e:
                    print("An error occurred:", e)
                    break

if __name__ == "__main__":
    key = b'some_16_byte_key___'  # Ensure the key is correctly set
    server_respond(key)

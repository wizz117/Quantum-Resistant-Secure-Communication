import socket
from aes_encryption import aes_encrypt, aes_decrypt

def generate_quantum_key():
    return b'some_16_byte_key___' 

def client_send_and_receive(message, key):
    host, port = '127.0.0.1', 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        # Send initial message
        iv, tag, encrypted_message = aes_encrypt(message.encode(), key)
        full_message = iv + tag + encrypted_message
        s.sendall(full_message)
        print("Message sent to server.")

        # Receive and print the server's first response
        full_response = s.recv(1024)
        iv = full_response[:12]
        tag = full_response[12:28]
        encrypted_response = full_response[28:]
        response = aes_decrypt(iv, tag, encrypted_response, key)
        print("First response from server:", response.decode())

if __name__ == "__main__":
    key = generate_quantum_key()
    client_send_and_receive("McElece: Hello from client!", key)

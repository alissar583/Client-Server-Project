import socket
import ssl
# from Crypto.Cipher import AES
import os
from cryptography.hazmat.primitives.asymmetric import rsa
import gnupg
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_session_key(session_key, public_key):
    encrypted_session_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_session_key


def receive_encrypted_session_key(ssl_socket):
    # Receive the length of the encrypted session key as a 4-byte integer
    # print(ssl_socket.recv(4))
    # key_length = int.from_bytes(ssl_socket.recv(4), byteorder='big')
    # print('key_length',  key_length)
    # Receive the encrypted session key
    encrypted_session_key = ssl_socket.recv(1024)
    print('encrypted_session_key: ')
    print(encrypted_session_key)
    return encrypted_session_key



def decrypt_session_key(encrypted_session_key, private_key):
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    # except InvalidSignature:
    #     print("Decryption error: Invalid signature")
    #     return None
    except Exception as e:
        print("Decryption error:", str(e))
        return None


def send_approval_to_client(ssl_socket):
    # Send an approval message to the client
    ssl_socket.send(b"Approved by the server!")


def load_private_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return key

def load_public_key_from_file(filename):
        with open(filename, 'rb') as key_file:
            key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return key

def decrypt(ciphertext, session_key):
    iv = ciphertext[:16]  # Extract IV from the ciphertext
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return decrypted_message.decode()


def create_tls_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8598))
    server_socket.listen(1)

    print("Waiting for a connection...")

    client_socket, addr = server_socket.accept()
    ssl_socket = client_socket
    print(f"Accepted connection from {addr}")

    # Create an SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server_new_certificate.pem", keyfile="server_new_private_key.pem")

    # Wrap the socket with TLS
    ssl_socket = context.wrap_socket(client_socket, server_side=True)

    # Perform the TLS handshake
    ssl_socket.do_handshake()

      # Load public key from file
    with open('server_new_public_key.pem', 'rb') as key_file:
        server_public_key = key_file.read()

    # Convert the loaded public key to a string
    # server_public_key_str = server_public_key.decode()
    user_name = ssl_socket.recv(1024).decode()
    print("user_name: ", user_name)
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    ssl_socket.send(b"Hello from the server!")
    ssl_socket.send(server_public_key)
    encrypted_session_key = receive_encrypted_session_key(ssl_socket)
    print('encrypted_session_key: ', encrypted_session_key)
    private_key = f'private_keys/{user_name}_private_key.pem'
    server_new_private_key = load_private_key_from_file(private_key)
    decrypted_session_key = decrypt_session_key(encrypted_session_key, server_new_private_key)
    print(f"Decrypted Session Key: {decrypted_session_key}")
    send_approval_to_client(ssl_socket)
    while True:
        encrypted_message = ssl_socket.recv(1024)
        # Decrypt message on the server side
        decrypted_message = decrypt(encrypted_message, decrypted_session_key)
        print("Decrypted Message on Server:", decrypted_message)
  
    # Close the connection
    ssl_socket.close()
    server_socket.close()


if __name__ == "__main__":
    create_tls_server()
  
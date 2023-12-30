import socket
import ssl
import os
# import gnupg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_session_key():
    # return os.urandom(8)  # Adjusted to generate a 16-byte key (128 bits)
    session_key = b'abdrere'
    return session_key


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

def send_encrypted_session_key(ssl_socket, encrypted_session_key):
    # Send the length of the encrypted session key as a 4-byte integer
    key_length = len(encrypted_session_key).to_bytes(4, byteorder='big')
    print('key_length')
    print(key_length)
    ssl_socket.send(key_length)

    # Send the encrypted session key
    ssl_socket.send(encrypted_session_key)
    # ssl_socket.send(b"Hello from the client!")


def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message


    def load_public_key_from_file(filename):
        with open(filename, 'rb') as key_file:
            key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return key


def create_tls_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8378))

    # Create an SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap the socket with TLS
    ssl_socket = context.wrap_socket(client_socket, server_hostname='localhost')
    # Perform the TLS handshake
    ssl_socket.do_handshake()

    with open('client_new_public_key.pem', 'rb') as key_file:
        client_public_key = key_file.read()

    # Send and receive data over the secure connection
    ssl_socket.send(b"Hello from the client!")
    ssl_socket.send(client_public_key)
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")

    # Load public key from file
    
    # Convert the loaded public key to a string
    # server_public_key_str = data.decode()

    # print(f"Loaded Server Public Key:\n{server_public_key_str}")
    # session_key = generate_session_key()
    # print('session_key: ', session_key)
    # # print(session_key)
    session_key = b'abdrere'
    public_key = load_public_key_from_file('test_public_key.pem')
    encrypted_session_key = encrypt_session_key(session_key, public_key)
    print('encrypted_session_key: ', encrypted_session_key)
    # print(encrypted_session_key)
    ssl_socket.send(encrypted_session_key)
    # send_encrypted_session_key(ssl_socket, encrypted_session_key)

    # ssl_socket.send(b"Hello from the client!")
    # ssl_socket.send(client_public_key)
    # data = ssl_socket.recv(1024)
    # print(f"Received: {data.decode()}")

    # Receive the approval message from the server
    # approval_message = ssl_socket.recv(1024)
    # print(f"Approval Message: {approval_message.decode()}")
    # data = ssl_socket.recv(1024)
    # print(f"Received: {data.decode()}")
    # Close the connection
    ssl_socket.close()

if __name__ == "__main__":
    create_tls_client()

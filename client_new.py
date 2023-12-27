import socket
import ssl
import os
# import gnupg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generate_session_key():
    return os.urandom(16)  # Adjusted to generate a 16-byte key (128 bits)

# def encrypt_session_key(session_key, public_key):
#     gpg_home = '/opt/homebrew/bin'  # Specify the path to the GPG executable
#     gpg = gnupg.GPG(gnupghome=gpg_home)
#     encrypted_data = gpg.encrypt(session_key, public_key)
#     print("GPG Status: ", gpg)
#     print('encrypted_data: ')
#     print(encrypted_data)
#     return encrypted_data

def encrypt_session_key(session_key, public_key_bytes):
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('encrypted_key: ', encrypted_key)
    return encrypted_key

def send_encrypted_session_key(ssl_socket, encrypted_session_key):
    # Send the length of the encrypted session key as a 4-byte integer
    key_length = len(encrypted_session_key).to_bytes(4, byteorder='big')
    print('key_length')
    print(key_length)
    ssl_socket.send(key_length)

    # Send the encrypted session key
    ssl_socket.send(encrypted_session_key.encode())
    # ssl_socket.send(b"Hello from the client!")


def create_tls_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    # Create an SSL context
    context = ssl.create_default_context()
    print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Wrap the socket with TLS
    ssl_socket = context.wrap_socket(client_socket, server_hostname='localhost')

    # Perform the TLS handshake
    ssl_socket.do_handshake()


    # Send and receive data over the secure connection
    ssl_socket.send(b"Hello from the client!")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")

    # Load public key from file
    with open('server_public_key.pem', 'rb') as key_file:
        server_public_key = key_file.read()

    # Convert the loaded public key to a string
    server_public_key_str = server_public_key.decode()

    print(f"Loaded Server Public Key:\n{server_public_key_str}")
    session_key = generate_session_key()
    print('session_key: ')
    print(session_key)
    encrypted_session_key = encrypt_session_key(session_key, server_public_key_str)
    print('encrypted_session_key: ')
    print(encrypted_session_key)
    send_encrypted_session_key(ssl_socket, encrypted_session_key)

    # ssl_socket.send(b"Hello from the client!")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")

    # Receive the approval message from the server
    # approval_message = ssl_socket.recv(1024)
    # print(f"Approval Message: {approval_message.decode()}")
    # data = ssl_socket.recv(1024)
    # print(f"Received: {data.decode()}")
    # Close the connection
    ssl_socket.close()

if __name__ == "__main__":
    create_tls_client()

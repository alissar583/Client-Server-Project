import socket
import ssl
# from Crypto.Cipher import AES
import os
# import gnupg
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def receive_encrypted_session_key(ssl_socket):
    # Receive the length of the encrypted session key as a 4-byte integer
    print(ssl_socket.recv(4))
    key_length = int.from_bytes(ssl_socket.recv(4), byteorder='big')
    print(key_length)
    # Receive the encrypted session key
    encrypted_session_key = ssl_socket.recv(key_length).decode()
    print('encrypted_session_key: ')
    print(encrypted_session_key)
    print(encrypted_session_key)
    return encrypted_session_key


# def decrypt_and_verify_session_key(encrypted_session_key, private_key):
#     gpg_home = '/opt/homebrew/bin'  # Specify the path to the GPG executable
#     gpg = gnupg.GPG(gnupghome=gpg_home)
#     gpg = gnupg.GPG()
#     gpg.import_keys(private_key)
#     print(f"Private Key: {private_key}")
#     print(f"Encrypted Session Key: {encrypted_session_key}")

#     decrypted_data = gpg.decrypt(encrypted_session_key)

#     print(f"Decryption Status: {decrypted_data.status}")
#     print(f"Decrypted Data: {decrypted_data.data}")

#     if not decrypted_data.ok:
#         print(f"Decryption failed: {decrypted_data.status}")

#     return decrypted_data.data


def decrypt_session_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('decrypted_key: ' ,decrypted_key)
    return decrypted_key


def send_approval_to_client(ssl_socket):
    # Send an approval message to the client
    ssl_socket.send(b"Approved by the server!")



def create_tls_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8838))
    server_socket.listen(1)

    print("Waiting for a connection...")

    client_socket, addr = server_socket.accept()
    print(f"Accepted connection from {addr}")

    # Create an SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server_certificate.pem", keyfile="server_new_private_key.pem")

    # Wrap the socket with TLS
    ssl_socket = context.wrap_socket(client_socket, server_side=True)

    # Perform the TLS handshake
    ssl_socket.do_handshake()

      # Load public key from file
    with open('server_private_key.pem', 'rb') as key_file:
        server_public_key = key_file.read()

    # Convert the loaded public key to a string
    server_public_key_str = server_public_key.decode()

    print(f"Loaded Server Public Key:\n{server_public_key_str}")


    encrypted_session_key = receive_encrypted_session_key(ssl_socket)
    print(encrypted_session_key)
    decrypted_session_key = decrypt_and_verify_session_key(encrypted_session_key, server_public_key_str)
    # decrypted_session_key = decrypt_and_verify_session_key(encrypted_session_key, private_key)
    if decrypted_session_key is not None:
        print(f"Decrypted Session Key: {decrypted_session_key}")
    else:
        print("Failed to decrypt session key.")
    print(decrypted_session_key)
    send_approval_to_client(ssl_socket)


    # Send and receive data over the secure connection
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")

    ssl_socket.send(b"Hello from the server!")

    # Close the connection
    ssl_socket.close()
    server_socket.close()

if __name__ == "__main__":
    create_tls_server()

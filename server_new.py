import socket
import ssl
# from Crypto.Cipher import AES
import os
from cryptography.hazmat.primitives.asymmetric import rsa
import gnupg
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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

# def decrypt_message(private_key, encrypted_message):
#     decrypted_message = private_key.decrypt(
#         encrypted_message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return decrypted_message


# def decrypt_session_key(encrypted_key, private_key):
#     decrypted_key = private_key.decrypt(
#         encrypted_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     print('decrypted_key: ' ,decrypted_key)
#     return decrypted_key



# def decrypt_session_key(encrypted_key, private_key_bytes):
    print('tesssty', encrypted_key)
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=b'abd12',
        backend=default_backend()
    )
    # print('private_keyL: ', private_key)
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print('decrypted_key: ', decrypted_key)
    return decrypted_key


def decrypt_session_key(encrypted_session_key, private_key):
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key


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

def create_tls_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8378))
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

    # print(f"Loaded Server Public Key:\n{server_public_key_str}")

    # Send and receive data over the secure connection
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    ssl_socket.send(b"Hello from the server!")
    ssl_socket.send(server_public_key)
    encrypted_session_key = receive_encrypted_session_key(ssl_socket)
    print('encrypted_session_key: ', encrypted_session_key)
    # with open('server_new_private_key.pem', 'rb') as key_file:
    #     server_new_private_key = key_file.read()
    server_new_private_key = load_private_key_from_file('test_private_key.pem')
    decrypted_session_key = decrypt_session_key(encrypted_session_key, server_new_private_key)
    print(f"Decrypted Session Key: {decrypted_session_key}")

    # Close the connection
    ssl_socket.close()
    server_socket.close()


def generate_key_pair():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used value for the public exponent
        key_size=2048,  # Key size in bits
        backend=default_backend(),
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save the private key to a file
    with open("server_private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    # Save the public key to a file
    with open("server_public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key_pem)


def test():
      # Load key pair
    loaded_private_key = load_private_key_from_file('test_private_key.pem')
    loaded_public_key = load_public_key_from_file('test_public_key.pem')

    # Example session key
    session_key = b'abdrere'

    # Encrypt session key using the public key
    encrypted_session_key = encrypt_session_key(session_key, loaded_public_key)
    print(f'Encrypted Session Key: {encrypted_session_key}')
    # encrypted_session_key = b'\xa1\x99k\x18\xe1\xe1\x1d\xaa\xe7t\xb5\x80\x97O\xe2@\xe4\xb1\xf8"\x91ha\x9d\xb9P\xba\n7\xa8\xc0\x8ds\x1f\x82\xd4\xac\'\x1f Z\x06\xacVB\x85\xec\xb3\x1e\x02O+G\xfc\xd2\\\xce\x9e\x03\xf2$!#\x7f\x0fB\x18LAC/\xf3\xe6\xc3U\x1d\xb5\xea\xf9\x1b\x1bs\xfb\xe2\x8b\xec\xbb\xf7\x99/\x1d\xa7\xfa\x84\xdc\xbf\x99\'\x16F.\x9a\x14\x1f\x88{\x14\xb4\xab\xb0k\xcb\xef{\xe9LMe\xf6\x83IZ\xc2\'\xe1\x83\xdc\xe23\xb2\x14\'\x88\x80\xb0\xc1"]\x03Y\x97A\xc94\x058M;Cs\x8b\'\x17*\xbe\x05\xc9\x92W5\xbc\x1f\xf5d\x13z\xe1\x96\xca\xce\x85\'\x92p<5\x9a\x14\xa2o\xa27\xa5\xea\xfa\x16\xb7N{\x80\x82;\x16\xcf\x89\x97Bs.\x04\x9c\xfc\xd1\xe4\x92\xfe\xf0(\xc3\x10\x04Q\x1aC\xae\xe5\x9d\x1ey\xb8~\xce\x7fB\x8f_w\xf1\xe1\xb1\xd0``\x11@h\xca\x1e\xfb\xb8<R\xf7\x18\xf5\x03\x18\x81(\xcd\x0c\xf6\xec\xda\xc9\xb6'
    # Decrypt session key using the private key
    decrypted_session_key = decrypt_session_key(encrypted_session_key, loaded_private_key)
    print(f'Decrypted Session Key: {decrypted_session_key}')

if __name__ == "__main__":
    # generate_key_pair()
    create_tls_server()
    # test()
  
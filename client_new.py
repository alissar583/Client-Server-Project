import socket
import ssl
import os
import jwt
# import gnupg
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



# def generate_session_key():
#     return os.urandom(16)  # Adjusted to generate a 16-byte key (128 bits)


def generate_session_key(username, password, salt):
    # Combine username and password for uniqueness
    combined_info = f"{username}:{password}"
    info_bytes = combined_info.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000, 
        backend=default_backend()
    )
    return kdf.derive(info_bytes)


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


def encrypt(message, session_key):
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext


def decode_token(token, entity):
    secret_key = "myapp"  # Replace with your own secret key
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        if entity == "role_id":
            role_id = decoded_token.get("role_id")
            return role_id
        if entity == "username":
            username = decoded_token.get("username")
            return username

    except jwt.DecodeError:
        print("Invalid token")
        return None


def generate_key_pair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,  
        backend=default_backend(),
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_filename = f"private_keys/{username}_private_key.pem"
    public_key_filename = f"public_keys/{username}_public_key.pem"
    with open(private_key_filename, "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    with open(public_key_filename, "wb") as public_key_file:
        public_key_file.write(public_key_pem)

def generate_token(username, role_id):
    # Generate a JWT token using the username and role_id
    payload = {"username": username, "role_id": role_id}
    secret_key = "myapp"  
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token


def create_tls_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8478))
    # Create an SSL context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Wrap the socket with TLS
    ssl_socket = context.wrap_socket(client_socket, server_hostname='localhost')
    ssl_socket.do_handshake()
    token = generate_token('abd', 1)
    print(token)
    token = input("Enter token: ")
    username = decode_token(token, 'username')
    ssl_socket.send(username.encode())
    print('user_name ', username)
    generate_key_pair(username)
    public_key = f'public_keys/{username}_public_key.pem'
    private_key = f'private_keys/{username}_private_key.pem'
    with open(public_key, 'rb') as key_file:
        client_public_key = key_file.read()

    ssl_socket.send(b"Hello from the client!")
    ssl_socket.send(client_public_key)
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    username = username
    password = "123456"
    salt = os.urandom(16)  # Generate a random salt for each user session

    session_key = generate_session_key(username, password, salt)
    print('session_key: ', session_key)

    public_key = load_public_key_from_file(public_key)
    encrypted_session_key = encrypt_session_key(session_key, public_key)
    print('encrypted_session_key: ', encrypted_session_key)
    # print(encrypted_session_key)
    ssl_socket.send(encrypted_session_key)
    data = ssl_socket.recv(1024)
    print(f"Received: {data.decode()}")
    while True:
        message_to_server = input('enter your message: ')
        encrypted_message = encrypt(message_to_server, session_key)
        ssl_socket.send(encrypted_message)

    ssl_socket.close()

if __name__ == "__main__":
    create_tls_client()

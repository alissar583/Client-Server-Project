import socket
from database import db
from cryptography.fernet import Fernet
import json
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

################
# Generate the private key
# server_private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

# # Extract the public key
# server_public_key = server_private_key.public_key()

# # Serialize and save the public key to a file
# public_key_pem = server_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# with open("server_public_key.pem", "wb") as f:
#     f.write(public_key_pem)

# # Serialize and save the private key to a file (keep it secure)
# private_key_pem = server_private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# )

# with open("server_private_key.pem", "wb") as f:
#     f.write(private_key_pem)

# # Generate the private key
# client_private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

# # Extract the public key
# client_public_key = client_private_key.public_key()

# # Serialize and save the public key to a file
# public_key_pem = client_public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# with open("client_public_key.pem", "wb") as f:
#     f.write(public_key_pem)

# # Serialize and save the private key to a file (keep it secure)
# private_key_pem = client_private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# )

# with open("client_private_key.pem", "wb") as f:
#     f.write(private_key_pem)

# # Handshaking with the server
# def handshake(server_public_key):
#     # Client sends its public key to the server
#     client_public_key_bytes = client_public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

#     # Server receives and stores the client's public key
#     received_client_public_key = serialization.load_pem_public_key(
#         client_public_key_bytes,
#         backend=default_backend()
#     )

#     # Server sends its public key to the client
#     server_public_key_bytes = server_public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

#     # Client receives and stores the server's public key
#     received_server_public_key = serialization.load_pem_public_key(
#         server_public_key_bytes,
#         backend=default_backend()
#     )

#     return received_server_public_key, received_client_public_key

# # Generate session key
# def generate_session_key():
#     return os.urandom(32)  # 256-bit key

# def generate_iv():
#     # Generate a secure random IV
#     salt = b'salt_1234'  # Salt value for key derivation
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=16,  # IV length (16 bytes)
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     iv = kdf.derive(b'')  # Derive the IV using an empty password/key
#     return iv


# def encrypt(plaintext, session_key):
#     block_size = 16  # AES block size is 16 bytes

#     # Pad the plaintext data
#     padding_length = block_size - (len(plaintext) % block_size)
#     padded_plaintext = plaintext + bytes([padding_length] * padding_length)

#     iv = generate_iv()  # Invoke the generate_iv function to obtain the IV
#     cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
#     return iv + ciphertext

# def decrypt(ciphertext, session_key):
#     block_size = 16  # AES block size is 16 bytes

#     iv = generate_iv()   # Extract the IV from the ciphertext
#     ciphertext = ciphertext[block_size:]  # Remove the IV from the ciphertext

#     cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#     # Remove the PKCS7 padding from the plaintext
#     padding_length = padded_plaintext[-1]
#     plaintext = padded_plaintext[:-padding_length]

#     return plaintext

# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="

# Create a Fernet cipher object using the key
cipher = Fernet(key)

def update_record_by_username(username, new_value):
    # Establish a connection to the MySQL database
    connection = mysql.connector.connect(host="localhost", user="root", database="chat")

    # Create a cursor object to execute SQL queries
    cursor = connection.cursor()

    update_query = """
    UPDATE users
    SET phone = %s
    WHERE username = %s
    """
    values = (new_value, username)
    cursor.execute(update_query, values)

    # Commit the changes and close the connection
    connection.commit()
    cursor.close()
    connection.close()


def handle_request(client_socket):
    request = client_socket.recv(1024)
    # Decrypt the data using the cipher
    decrypted_data = cipher.decrypt(request)
    # Convert the decrypted data to string
    request_data = decrypted_data.decode()
    print("Request:", request_data)
     # Deserialize the received JSON to retrieve the original list
    request_data_list = json.loads(request_data)

    if 'request_choice' in request_data_list:
     if request_data_list.get('request_choice') == "4":
       
    #     # Process the request and perform the necessary operations
        username = request_data_list.get('username')
        value = request_data_list.get('phone')
        update_record_by_username(username, value)

    response = "Success"  
    # Convert the response to bytes
    response_data = response.encode()
    # Encrypt the response data using the cipher
    encrypted_data = cipher.encrypt(response_data)

    client_socket.sendall(encrypted_data)
    client_socket.close()


def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("Server started. Listening on {}:{}".format(host, port))

    while True:
        client_socket, addr = server_socket.accept()
        handle_request(client_socket)


if __name__ == "__main__":
    host = "127.0.0.1"  # Replace with your desired server IP
    port = 8080  # Replace with your desired server port
    start_server(host, port)

    #  # Handshake with the server
    # server_public_key = None  # Load the server's public key from file or database

    #     # Load the server's public key from file
    # with open("server_public_key.pem", "rb") as f:
    #     server_public_key = serialization.load_pem_public_key(
    #         f.read(),
    #         backend=default_backend()
    #     )

    # server_public_key, _ = handshake(server_public_key)

    # # Client generates session key and sends it to the server using PGP
    # session_key = generate_session_key()
    # encrypted_session_key = server_public_key.encrypt(
    #     session_key,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )

    # # Send the encrypted session key to the server
    # client_socket.sendall(encrypted_session_key)

    # # Wait for the encrypted response from the server
    # encrypted_response = client_socket.recv(1024)

    # # Decrypt the response from the server using the session key
    # decrypted_response = decrypt(encrypted_response, session_key)

    # # Process the decrypted response
    # print("Received response from server:", decrypted_response.decode())

    # # Send completed projects to the server
    # data = "Completed projects data"  # Replace with your actual data
    # encrypted_data = encrypt(data.encode(), session_key)
    # client_socket.sendall(encrypted_data)

    # # Wait for the confirmation message from the server
    # encrypted_confirmation = client_socket.recv(1024)

    # # Decrypt the confirmation message using the session key
    # decrypted_confirmation = decrypt(encrypted_confirmation, session_key)

    # # Process the decrypted confirmation message
    # print("Received confirmation from server:", decrypted_confirmation.decode())

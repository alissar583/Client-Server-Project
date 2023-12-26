import socket
from database import db
from cryptography.fernet import Fernet
import json
import mysql.connector
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="

# Create a Fernet cipher object using the key
cipher = Fernet(key)

def load_server_private_key():
    # Load the university doctor's private key from a PEM file
    with open('server_private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_server_public_key():
    # Load the university doctor's public key from a PEM file
    with open('server_public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key():
    # Load the university doctor's private key from a PEM file
    with open('client_private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key():
    # Load the university doctor's public key from a PEM file
    with open('client_public_key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def sign_data(data):
    # Load the university doctor's private key
    private_key = load_server_private_key()

    # Sign the data using the private key
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Convert the signature to a base64-encoded string
    signature_str = base64.b64encode(signature).decode('utf-8')

    return signature_str

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

def verify_signature(data, signature):
    # Load the university doctor's public key from a file or other source
    public_key = load_public_key()
    # print("dataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa in verify",data.encode())

    try:
        # Verify the signature using the public key
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True
    except Exception:
        return False
        
def handle_request(client_socket):
    request = client_socket.recv(1024)
    # Decrypt the data using the cipher
    decrypted_data = cipher.decrypt(request)
    # Convert the decrypted data to string
    request_data = decrypted_data.decode()
    print("Request:", request_data)
    #  # Deserialize the received JSON to retrieve the original list
    # request_data_list = json.loads(request_data)

    request_data_json = json.loads(request_data)

    #################
    if isinstance(request_data_json, dict):
    # It's already a dictionary, proceed with further processing
    # Access the dictionary values as needed

     request_signature = request_data_json['signature']
     request_data = request_data_json["data"]    # Continue processing the request as needed

    # Verify the signature using the university doctor's public key
     is_valid_signature = verify_signature(request_data, request_signature)

     if is_valid_signature:
        print("Signature is valid.")
        print("Request:", request_data)
        # Process the request and perform the necessary operations
        response = "Valid Signature"

     else:
        print("Signature is not valid.")
        response = "Invalid Signature"

    # Create a dictionary to hold the response data and signature
     signed_response_data = {
        "data": response,
        "signature": sign_data(response)
     }
    # print("responnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnce",response)


    # Convert the signed_response_data to JSON string
     signed_response_data_json = json.dumps(signed_response_data)

    # Encrypt the response data using the cipher
     encrypted_data = cipher.encrypt(signed_response_data_json.encode())
    else:
      encrypted_data = cipher.encrypt(request_data_json.encode())

    client_socket.sendall(encrypted_data)
    client_socket.close()
    ##################33333
    # if 'request_choice' in request_data_list:
    #  if request_data_list.get('request_choice') == "4":
       
    # #     # Process the request and perform the necessary operations
    #     username = request_data_list.get('username')
    #     value = request_data_list.get('phone')
    #     update_record_by_username(username, value)

    # response = "Success"  
    # # Convert the response to bytes
    # response_data = response.encode()
    # # Encrypt the response data using the cipher
    # encrypted_data = cipher.encrypt(response_data)

    # client_socket.sendall(encrypted_data)
    # client_socket.close(

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("Server started. Listening on {}:{}".format(host, port))

    while True:
        client_socket, addr = server_socket.accept()
        handle_request(client_socket)

def generate_key_pair():
    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used value for the public exponent
        key_size=2048,  # Key size in bits
        backend=default_backend()
    )

    # Get the public key from the private key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the private key to a file
    with open('server_private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key_pem)

    # Save the public key to a file
    with open('server_public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key_pem)

if __name__ == "__main__":
    host = "127.0.0.1"  # Replace with your desired server IP
    port = 8081  # Replace with your desired server port
    generate_key_pair()
    start_server(host, port)

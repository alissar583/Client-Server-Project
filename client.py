import socket
import json
import mysql.connector
import jwt
from cryptography.fernet import Fernet
import json
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="
# Create a Fernet cipher object using the key
cipher = Fernet(key)

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

def verify_signature(data, signature):
    # Load the university doctor's public key from a file or other source
    public_key = load_public_key()

    try:
        # Verify the signature using the public key
        public_key.verify(
            signature,
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
        
def sign_data(data):
    # Load the university doctor's private key
    private_key = load_private_key()

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

def send_request(host, port, request_data):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Convert request_data to string if it's a dictionary
    if isinstance(request_data, dict):
        request_data = str(request_data)

    # Convert request_data to bytes
    request_data_bytes = request_data.encode()

    ################
    # Generate a hash of the request data
    hash_value = hashlib.sha256(request_data_bytes).hexdigest()

    # Sign the hash with the university doctor's private key
    # Replace the following line with the actual signing process
    signature = sign_data(hash_value)

    # Create a dictionary to hold the request data and signature
    signed_data = {"data": request_data, "signature": signature}

    # Convert the signed_data to JSON string
    signed_data_json = json.dumps(signed_data)

   # Encrypt the data using the cipher
    encrypted_data = cipher.encrypt(signed_data_json.encode())

    client_socket.sendall(encrypted_data)

    response = client_socket.recv(1024)
    decrypted_data = cipher.decrypt(response)
    response_data = decrypted_data.decode()

    # Verify the digital signature received from the server
    response_data_json = json.loads(response_data)
    response_signature = response_data_json.get("signature")
    response_data = response_data_json.get("data")

    # Verify the signature using the university doctor's public key
    is_valid_signature = verify_signature(response_data, response_signature)

    if is_valid_signature:
        print("Signature is valid.")
        print("Response:", response_data)
    else:
        print("Signature is not valid.")

    client_socket.close()
    return response_data
    ###################
    # encrypted_data = cipher.encrypt(request_data_bytes)
    # client_socket.sendall(encrypted_data)

    # response = client_socket.recv(1024)
    # decrypted_data = cipher.decrypt(response)
    # response_data = decrypted_data.decode()
    # print("Response:", response_data)

    # client_socket.close()
    # return response_data


def user_exists(username):
    # Query the database to check if the user exists
    connection = mysql.connector.connect(host="localhost", user="root", database="chat")
    cursor = connection.cursor()

    query = "SELECT COUNT(*) FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    count = result[0]

    cursor.nextset()  # Move to the next result set
    cursor.close()
    connection.close()

    return count > 0


def get_user_role_id(username):
    # Query the database to get the role_id of the user
    connection = mysql.connector.connect(host="localhost", user="root", database="chat")
    cursor = connection.cursor()

    query = "SELECT role_id FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    role_id = result[0]

    cursor.nextset()  # Move to the next result set
    cursor.close()
    connection.close()

    return role_id


def generate_token(username, role_id):
    # Generate a JWT token using the username and role_id
    payload = {"username": username, "role_id": role_id}
    secret_key = "myapp"  # Replace with your own secret key
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token


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


def get_user_role(role_id):
    # Query the database to get the role information of the user
    connection = mysql.connector.connect(host="localhost", user="root", database="chat")
    cursor = connection.cursor()

    query = """
        SELECT roles.name
        FROM roles
        JOIN users ON users.role_id = roles.id
        WHERE roles.id = %s
    """
    cursor.execute(query, (role_id,))  # Pass role_id as a tuple
    result = cursor.fetchone()
    role_name = result[0] if result else None

    cursor.nextset()  # Move to the next result set
    cursor.close()
    connection.close()

    return role_name


def store_user_in_database(username, password, role_id, exists):
    # Establish a connection to the MySQL database
    connection = mysql.connector.connect(host="localhost", user="root", database="chat")

    # Create a cursor object to execute SQL queries
    cursor = connection.cursor()

    # Create a table for user information if it doesn't exist
    create_users_query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            phone VARCHAR(255) NULL,
            role_id INT,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
    """

    create_roles_query = """
        CREATE TABLE IF NOT EXISTS roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL
        )
    """
    cursor.execute(create_roles_query)
    cursor.execute(create_users_query)

    if exists == False:
        # Insert the user information into the table
        insert_query = """
        INSERT INTO users (username, password, role_id)
        VALUES (%s, %s, %s)
       """
        values = (username, password, role_id)
        cursor.execute(insert_query, values)

    # Commit the changes and close the connection
    connection.commit()
    cursor.close()
    connection.close()


if __name__ == "__main__":
    host = "127.0.0.1"  # Replace with your server IP
    port = 8080  # Replace with your server port

    # Prompt the user for input

    request_choice = input(
        "Enter '1' to login or '2' to create an account or '3' to access university system or '4' to complete your info: "
    )

    if request_choice == "1":
        username = input("Enter username: ")
        password = input("Enter password: ")

        if user_exists(username):
            exists = True
            # User exists, send login request
            request_login = {
                "action": "LOGIN",
                "username": username,
                "password": password,
            }

            json_data = json.dumps(request_login)

            response = send_request(host, port, json_data)
        else:
            print("User does not exist. Please create an account.")

    elif request_choice == "2":
        username = input("Enter username: ")
        password = input("Enter password: ")
        role_id = input("Enter role: ")

        exists = False
        # User does not exist, send create account request
        request_create_account = {
            "action": "CREATE_ACCOUNT",
            "username": username,
            "password": password,
            "role_id": role_id,
        }

        json_data = json.dumps(request_create_account)

        response = send_request(host, port, json_data)
        # Store the user in the database
        store_user_in_database(username, password, role_id, exists)

    elif request_choice == "3":
        token = input("token: ")
        role_id = decode_token(token, "role_id")
        role_name = get_user_role(role_id)

        userRole = {"action": "till user what are thier userRole", "role": role_name}

        json_data = json.dumps(userRole)

        response = send_request(host, port, json_data)
        print("Welcome as:", role_name)

    elif request_choice == "4":
        token = input("Enter Your Token: ")
        phone = input("Enter Your Phone Number: ")

        request_data = {
            "token": token,
            "phone": phone,
            "username": decode_token(token, "username"),
            "request_choice": "4",
        }

        json_data = json.dumps(request_data)

        send_request(host, port, json_data)

    else:
        print("Invalid choice.")

    # Generate and return the token with the response
    if request_choice == "1" or request_choice == "2":
        role_id = get_user_role_id(username)
        token = generate_token(username, role_id)
        print("Token:", token)

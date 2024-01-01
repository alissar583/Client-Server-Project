import socket
import json
import mysql.connector
import jwt
from cryptography.fernet import Fernet
import json
import hashlib
import base64
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding


# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="
# Create a Fernet cipher object using the key
cipher = Fernet(key)


def load_server_public_key():
    # Load the university doctor's public key from a PEM file
    with open("server_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def load_private_key(username):
    # Load the university doctor's private key from a PEM file
    with open(f"{username}_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def verify_signature(data, signature):
    # Load the university doctor's public key from a file or other source
    public_key = load_server_public_key()

    try:
        # Verify the signature using the public key
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        return True
    except Exception:
        return False


def sign_data(data, username):
    # Load the university doctor's private key
    private_key = load_private_key(username)

    # print("dataaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa in sign",data.encode())

    # Sign the data using the private key
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    # Convert the signature to a base64-encoded string
    signature_str = base64.b64encode(signature).decode("utf-8")

    return signature_str


def send_request(host, port, request_data):
    # Convert request_data to string if it's a dictionary
    if isinstance(request_data, dict):
        request_data = str(request_data)

    response_data_python = json.loads(json_data)

    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Load the doctor's digital certificate and private key
    context.load_cert_chain(
        certfile=f'{response_data_python["username"]}_certificate.pem',
        keyfile=f'{response_data_python["username"]}_private_key.pem',
    )

    # Establish a secure connection to the server
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            # Your secure connection is now established
            # You can send and receive data using the 'ssock' object
            ssock.sendall(b"Hello, server!")
            response = ssock.recv(4096)
            print(response.decode())

    if (
        "request_choice" in response_data_python
        and response_data_python["request_choice"] == "5"
    ):
        signature = sign_data(
            response_data_python["markes"], response_data_python["username"]
        )
        # Create a dictionary to hold the request data and signature
        signed_data = {
            "data": response_data_python["markes"],
            "signature": signature,
            "username": response_data_python["username"],
        }
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

    else:
        # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # client_socket.connect((host, port))
        # Convert the signed_data to JSON string
        data = json.dumps(request_data)
        # Encrypt the data using the cipher
        encrypted_data = cipher.encrypt(data.encode())
        # print("encrypted data:", encrypted_data)
        client_socket.sendall(encrypted_data)

        response = client_socket.recv(1024)
        # print("responce data before decrypt:", response)
        decrypted_data = cipher.decrypt(response)
        response_data = decrypted_data.decode()
        # print("Response", response_data)

    client_socket.close()
    return response_data
    ###################


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
    # cursor.close()
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
    # print("roooooooooooooooooooooooooooooooole",role_id)
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
    print("queryyyyyyyyyyyyyyyyyyyyyyyyyyy", result)

    role_name = result[0] if result else None

    cursor.nextset()  # Move to the next result set
    # print("fincal",role_name)

    # cursor.close()
    connection.close()
    print("ffff", role_name)

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


def generate_key_pair(username):
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

    # Create unique filenames for the keys using the username
    private_key_filename = f"{username}_private_key.pem"
    public_key_filename = f"{username}_public_key.pem"
    # Save the private key to a file
    with open(private_key_filename, "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    # Save the public key to a file
    with open(public_key_filename, "wb") as public_key_file:
        public_key_file.write(public_key_pem)


def generate_csr(private_key, common_name, username):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    csrfilename = f"{username}_csr.csr"

    with open(csrfilename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def generate_csr_with_permissions(private_key, common_name, username, permissions):
    custom_extension_oid = ObjectIdentifier("1.2.3.4.5")
    permissions_string = ",".join(permissions).encode(
        "utf-8"
    )  # Convert list to string and encode as bytes

    # DER-encode the permissions string
    permissions_der = der_encoder.encode(univ.OctetString(permissions_string))

    extension = x509.SubjectAlternativeName(
        [x509.OtherName(custom_extension_oid, permissions_der)]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(extension, False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    csrfilename = f"{username}_csr.csr"

    with open(csrfilename, "wb") as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))

    return csr


def read_permissions_from_csr(csr_filename):
    with open(f"{csr_filename}_certificate.pem", "rb") as cert_file:
        # print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        csr = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    print("extensions asd", csr.extensions)
    permissions_extension = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    print("extensions asd", permissions_extension)
    if isinstance(permissions_extension.value, x509.SubjectAlternativeName):
        print("dsds", permissions_extension.value)
        for name in permissions_extension.value:
            if isinstance(name, x509.OtherName) and name.type_id == ObjectIdentifier(
                "1.2.3.4.5"
            ):
                permissions_der = name.value
                permissions_string = permissions_der.decode(
                    "utf-8"
                )  # Decode the DER-encoded permissions to a string
                permissions = permissions_string.split(
                    ","
                )  # Split the string into a list of permissions
                # print('permissionspermissions', permissions)
                return permissions
    # Return an empty list if the permissions extension was not found or does not contain the expected values
    return []
    permissions_der = permissions_extension.value.value
    permissions_string = permissions_der.decode(
        "utf-8"
    )  # Decode the DER-encoded permissions to a string
    permissions = permissions_string.split(
        ","
    )  # Split the string into a list of permissions

    return permissions


def load_csr_file(username):
    # Load the university doctor's private key from a PEM file
    with open(f"{username}_csr.csr", "rb") as csr_file:
        csr_data = csr_file.read()

    return csr_data


def send_csr(host, port, data, username):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    # Create a dictionary to hold the data
    data = {
        "csr_file": data.decode("latin-1"),  # Convert binary data to string
        "username": username,
    }

    # Convert the dictionary to JSON
    json_data = json.dumps(data)
    # print("ppppppppppppppppppppppppp",json_data.encode())

    # Send the JSON data over the socket
    client_socket.sendall(json_data.encode())
    # client_socket.sendall(data)

    response = client_socket.recv(2048)
    with open(f"{username}_certificate.pem", "wb") as cert_file:
        cert_file.write(response)

    # per = read_permissions_from_csr(username)
    # print('permissions certiff', per)
    # print("responce data before decrypt:", response)
    client_socket.close()
    return response


# Generate key pair for the university doctor
# private_key, public_key = generate_key_pair()

if __name__ == "__main__":
    host = "127.0.0.1"  # Replace with your server IP
    port = 8081  # Replace with your server port

    # Prompt the user for input

    request_choice = input(
        "Enter '1' to create an account or '2' to login or '3' to access university system or '4' to complete your info or '5' to submet markes: "
    )

    if request_choice == "1":
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

        if role_id == "2":
            generate_key_pair(username)
            common_name = "University Doctor"
            csr = generate_csr(load_private_key(username), common_name, username)
            csr = load_csr_file(username)
            # print("fe2",csr)
            send_csr(host, port, csr, username)

            # print("cccccccccccccccccccccc",csr)
        if role_id == "1":
            generate_key_pair(username)
            common_name = "University Student"
            csr = generate_csr(load_private_key(username), common_name, username)
            csr = load_csr_file(username)
            send_csr(host, port, csr, username)
            per = read_permissions_from_csr(username)
            print("client permisssions csr: ", per)

        json_data = json.dumps(request_create_account)

        response = send_request(host, port, json_data)
        # Store the user in the database
        store_user_in_database(username, password, role_id, exists)

    elif request_choice == "2":
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

            # print("Response",response)

        else:
            print("User does not exist. Please create an account.")

    elif request_choice == "3":
        token = input("token: ")
        role_id = decode_token(token, "role_id")

        role_name = get_user_role(role_id)
        # print("Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        userRole = {"action": "till user what are thier userRole", "role": role_name}

        json_data = json.dumps(userRole)

        # print("Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
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
        print("Updated Succefully")

    elif request_choice == "5":
        token = input("Enter Your Token: ")
        markes = input("Enter The Markes:")

        if decode_token(token, "role_id") == 2:
            username = decode_token(token, "username")
            # generate_key_pair(username)

            request_data = {
                "action": "Enter Markes",
                "markes": markes,
                "request_choice": "5",
                "username": username,
            }

            json_data = json.dumps(request_data)

            send_request(host, port, json_data)
            print("Sended Markes Succefully")

        else:
            print("Invalid Request")

    else:
        print("Invalid choice.")

    # Generate and return the token with the response
    if request_choice == "1" or request_choice == "2":
        role_id = get_user_role_id(username)
        token = generate_token(username, role_id)
        print("Token:", token)

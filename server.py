import socket
from database import db
from cryptography.fernet import Fernet
import json
import ssl
import mysql.connector
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="

# Create a Fernet cipher object using the key
cipher = Fernet(key)


def load_server_private_key():
    # Load the university doctor's private key from a PEM file
    with open("server_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def load_server_public_key():
    # Load the university doctor's public key from a PEM file
    with open("server_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def load_ca_private_key():
    with open("ca_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    return private_key


def load_ca_certificate():
    with open("ca_certificate.pem", "rb") as cert_file:
        ca_certificate_data = cert_file.read()

    ca_certificate = x509.load_pem_x509_certificate(
        ca_certificate_data, default_backend()
    )
    return ca_certificate


def load_public_key(username):
    # Load the university doctor's public key from a PEM file
    with open(f"{username}_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def sign_data(data):
    # Load the university doctor's private key
    private_key = load_server_private_key()

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


def verify_signature(data, signature, username):
    # Load the university doctor's public key from a file or other source
    public_key = load_public_key(username)

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


def verify_identity(csr_file_path, doctor_public_key):
    #  Parse the CSR
    csr = x509.load_pem_x509_csr(csr_file_path, default_backend())

    #  Verify the association with Key P
    public_key = csr.public_key()
    if public_key != doctor_public_key:
        raise ValueError(
            "CSR public key does not match the expected doctor's public key."
        )
    else:
        print("DOCTOR RELATED WITH PUBLIC KEY")


def generate_certificate(csr_file, ca_private_key, ca_certificate, permissions):
    csr = x509.load_pem_x509_csr(csr_file, default_backend())

    # Create a new certificate based on the CSR
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_certificate.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(
        datetime.utcnow()
    )  # Set the validity period as needed
    builder = builder.not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    )  # Set the validity period as needed

    custom_extension_oid = ObjectIdentifier("1.2.3.4.5")
    permissions_string = ",".join(permissions).encode(
        "utf-8"
    )  # Convert list to string and encode as bytes

    # DER-encode the permissions string
    permissions_der = der_encoder.encode(univ.OctetString(permissions_string))

    extension = x509.SubjectAlternativeName(
        [x509.OtherName(custom_extension_oid, permissions_der)]
    )
    builder = builder.add_extension(
        extension, critical=False
    )  # Add any necessary extensions

    # Sign the certificate using the CA's private key
    certificate = builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # Serialize the certificate to PEM format
    certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    print("adasjdasvd", certificate_pem)
    return certificate_pem


def is_certificate_file(content):
    return content.startswith(
        "-----BEGIN CERTIFICATE REQUEST-----"
    ) or content.endswith("-----END CERTIFICATE REQUEST-----")


def is_csr_file(content):
    print("csr contet", content)
    return content.startswith(
        "-----BEGIN CERTIFICATE REQUEST-----"
    ) or content.endswith("-----END CERTIFICATE REQUEST-----")


def handle_request(client_socket):
    data = ssl_socket.recv(2048)
    decrypted_data = cipher.decrypt(data)
    response_data = decrypted_data.decode()
    print("Request:", request_data)

    request_data_json = json.loads(request_data)

    if isinstance(request_data_json, dict):
        request_signature = request_data_json["signature"]
        request_data = request_data_json[
            "data"
        ]  # Continue processing the request as needed

        # Verify the signature using the university doctor's public key
        is_valid_signature = verify_signature(
            request_data, request_signature, request_data_json["username"]
        )

        if is_valid_signature:
            print("Signature is valid.")
            print("Request:", request_data)
            # Process the request and perform the necessary operations
            response = "Valid Signature"

        else:
            print("Signature is not valid.")
            response = "Invalid Signature"

        # Create a dictionary to hold the response data and signature
        signed_response_data = {"data": response, "signature": sign_data(response)}

        # Convert the signed_response_data to JSON string
        signed_response_data_json = json.dumps(signed_response_data)

        # Encrypt the response data using the cipher
        encrypted_data = cipher.encrypt(signed_response_data_json.encode())
    else:
        # Send a response back to the client
        response = b"success!"
        print("ssend")
        encrypted_data = encrypt_data(response)
        # client_socket.sendall(encrypted_response)

    print("handlllll")
    ssl_socket.send(encrypted_data)
    # client_socket.close()


# def start_server(host, port):
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind((host, port))
#     server_socket.listen(5)
#     print("Waiting for a connection...")
#     client_socket, addr = server_socket.accept()
#     ssl_socket = client_socket
#     print(f"Accepted connection from {addr}")
#     # Create an SSL context
#     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#     context.load_cert_chain(
#         certfile="server_new_certificate.pem", keyfile="server_new_private_key.pem"
#     )
#     ssl_socket = context.wrap_socket(client_socket, server_side=True)
#     ssl_socket.do_handshake()

#     # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # server_socket.bind((host, port))
#     # server_socket.listen(6)

#     print("Server started. Listening on {}:{}".format(host, port))

#     while True:
#         # encrypted_message = ssl_socket.recv(1024)

#         # client_socket, addr = server_socket.accept()
#         handle_request(ssl_socket)


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


if __name__ == "__main__":
    host = "localhost"
    port = 8049
    # generate_key_pair()
    # start_server(host, port)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Waiting for a connection...")
    client_socket, addr = server_socket.accept()
    print(f"Accepted connection from {addr}")
    received_data = client_socket.recv(2048)
    print("request: ", received_data)
    try:
        data = received_data.decode()

        json_data = json.loads(data)
        csr_file_data = json_data["csr_file"].encode("latin-1")
        username = json_data["username"]
        verify_identity(csr_file_data, load_public_key(username))
        permissions = ["read_scientists_list", "write_data", "read_tes", "res"]
        certificate_to_doctor = generate_certificate(
            csr_file_data, load_ca_private_key(), load_ca_certificate(), permissions
        )
        print("DOCTOR CERTICATE GENERATED", certificate_to_doctor)
        client_socket.send(certificate_to_doctor)

        print(f"Accepted connection from {addr}")
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile="server_new_certificate.pem", keyfile="server_new_private_key.pem"
        )
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        ssl_socket.do_handshake()
        print("success do_handshake")

        while True:
            handle_request(client_socket)

    except:
        print("dfghj")
    #     print(f"Accepted connection from {addr}")
    #     # Create an SSL context
    #     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #     context.load_cert_chain(
    #         certfile="server_new_certificate.pem", keyfile="server_new_private_key.pem"
    #     )
    #     ssl_socket = context.wrap_socket(client_socket, server_side=True)
    #     ssl_socket.do_handshake()
    #     print("success do_handshake")

    #     while True:
    #         handle_request(client_socket)

    # json_data = json.loads(data)
    # csr_file_data = json_data["csr_file"].encode('latin-1')
    # username = json_data["username"]
    # verify_identity(csr_file_data, load_public_key(username))
    # permissions = ["read_scientists_list", "write_data", "read_tes", "res"]
    # certificate_to_doctor = generate_certificate(csr_file_data,load_ca_private_key(),load_ca_certificate(), permissions)
    # print("DOCTOR CERTICATE GENERATED",certificate_to_doctor)
    # client_socket.send(certificate_to_doctor)
    # while True:
    #     # encrypted_message = ssl_socket.recv(1024)

    #     # client_socket, addr = server_socket.accept()
    #     handle_request(client_socket)

    # generate_certificate()
    # handle_request(client_socket)

    # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_socket.bind(('localhost', port))
    # server_socket.listen(1)
    # print("Waiting for a connection...")
    # client_socket, addr = server_socket.accept()
    # ssl_socket = client_socket

    # print(f"Accepted connection from {addr}")
    # # Create an SSL context
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.load_cert_chain(certfile="server_new_certificate.pem", keyfile="server_new_private_key.pem")
    # ssl_socket = context.wrap_socket(client_socket, server_side=True)
    # ssl_socket.do_handshake()
    # print('success do_handshake')
    # data = ssl_socket.recv(2048)
    # print(f"Received: {data.decode()}")

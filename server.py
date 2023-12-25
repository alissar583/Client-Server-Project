import socket
from database import db
from cryptography.fernet import Fernet
import json
import mysql.connector

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

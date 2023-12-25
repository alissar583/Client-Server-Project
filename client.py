import socket
import json
import mysql.connector
import jwt
from cryptography.fernet import Fernet
import json

# Generate a random symmetric key
key = b"XaLc7Pd8qK5GJfEva0v1nZ0qDLgB8KkHRg9M8aIa8io="
# Create a Fernet cipher object using the key
cipher = Fernet(key)

# # Encrypt the data using the cipher
# encrypted_data = cipher.encrypt(b"Hello, server!")


def send_request(host, port, request_data):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    # Convert request_data to string if it's a dictionary
    if isinstance(request_data, dict):
        request_data = str(request_data)

    # Convert request_data to bytes
    request_data_bytes = request_data.encode()

    encrypted_data = cipher.encrypt(request_data_bytes)
    client_socket.sendall(encrypted_data)

    response = client_socket.recv(1024)
    decrypted_data = cipher.decrypt(response)
    response_data = decrypted_data.decode()
    print("Response:", response_data)

    client_socket.close()
    return response_data


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
            response = send_request(host, port, request_login)
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

        response = send_request(host, port, request_create_account)
        # Store the user in the database
        store_user_in_database(username, password, role_id, exists)

    elif request_choice == "3":
        token = input("token: ")
        role_id = decode_token(token, "role_id")
        role_name = get_user_role(role_id)

        userRole = {"action": "till user what are thier userRole", "role": role_name}

        response = send_request(host, port, userRole)
        print("Welcome as:", role_name)

    elif request_choice == "4":
        token = input("Enter Your Token: ")
        phone = input("Enter Your Phone Number: ")

        request_data = {
            "token": token,
            "phone": phone,
            "username": decode_token(token, "username"),
            "request_choice" : "4",
        }

        json_data = json.dumps(request_data)

        send_request(host, port,json_data)

    else:
        print("Invalid choice.")

    # Generate and return the token with the response
    if request_choice == "1" or request_choice == "2":
        role_id = get_user_role_id(username)
        token = generate_token(username, role_id)
        print("Token:", token)

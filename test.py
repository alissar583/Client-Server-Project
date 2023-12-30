from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return key

def load_key_from_file_b(filename):
    with open(filename, 'rb') as key_file:
        key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return key


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

# Example usage:

# Generate and save key pair
private_key, public_key = generate_key_pair()
save_key_to_file(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ),
    'test_private_key.pem'
)
save_key_to_file(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ),
    'test_public_key.pem'
)


if __name__ == "__main__":
    host = "127.0.0.1"  # Replace with your desired server IP
    port = 8081  # Replace with your desired server port

    # Load key pair
    loaded_private_key = load_key_from_file('test_private_key.pem')
    loaded_public_key = load_key_from_file_b('test_public_key.pem')

    # Example session key
    session_key = b'abdrere'

    # Encrypt session key using the public key
    encrypted_session_key = encrypt_session_key(session_key, loaded_public_key)
    print(f'Encrypted Session Key: {encrypted_session_key}')

    # Decrypt session key using the private key
    decrypted_session_key = decrypt_session_key(encrypted_session_key, loaded_private_key)
    print(f'Decrypted Session Key: {decrypted_session_key}')



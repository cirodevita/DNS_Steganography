from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Crypt:
    @staticmethod
    def generate_key():
        '''
        password = password_provided.encode()  # Convert to type bytes
        salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        '''

        key = Fernet.generate_key()

        file = open('key.key', 'wb')  # Open the file as wb to write bytes
        file.write(key)  # The key is type bytes still
        file.close()

    @staticmethod
    def encrypt(message):
        file = open('key.key', 'rb')  # Open the file as wb to read bytes
        key = file.read()  # The key will be type bytes
        file.close()

        message = message.encode()
        f = Fernet(key)
        encrypted = f.encrypt(message)

        return encrypted.decode('utf-8')

    @staticmethod
    def decrypt(message):
        file = open('key.key', 'rb')  # Open the file as wb to read bytes
        key = file.read()  # The key will be type bytes
        file.close()

        f = Fernet(key)
        return f.decrypt(bytes(message, 'utf8')).decode('utf-8')
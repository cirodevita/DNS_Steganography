import base64
from Crypto.Cipher import AES, XOR

password = "secretpassword"


class Crypt:
    @staticmethod
    def encrypt(message):
        cipher = XOR.new(password)
        return base64.b64encode(cipher.encrypt(message)).decode()

    @staticmethod
    def decrypt(message):
        cipher = XOR.new(password)
        return cipher.decrypt(base64.b64decode(message.encode())).decode()

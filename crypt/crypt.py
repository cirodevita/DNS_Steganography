import base64
from Crypto.Cipher import XOR

from configparser import ConfigParser

config = ConfigParser()
config.read('../configuration.ini')

password = config.get('CONFIG', 'password')


def encrypt(message):
    cipher = XOR.new(password)
    return base64.b64encode(cipher.encrypt(message)).decode()


def decrypt(message):
    cipher = XOR.new(password)
    return cipher.decrypt(base64.b64decode(message.encode())).decode()

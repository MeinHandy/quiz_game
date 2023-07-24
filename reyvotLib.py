# reyvot is a shitty util
from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import socket
import base64
import time
import rsa
import os


# https://stackoverflow.com/questions/12524994/encrypt-and-decrypt-using-pycrypto-aes-256#comment80992309_21928790
class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s.encode()) % self.bs) * chr(self.bs - len(s.encode()) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class Server:
    def __init__(self):
        self.server_private_key = None
        self.server_public_key = None
        self.names = []
        self.keys = []

    # Set up encryption
    def encryption_setup(self, public_key_name, private_key_name):  # Load public and private key
        if os.path.exists(public_key_name) and os.path.exists(private_key_name):
            self.server_public_key = rsa.PublicKey.load_pkcs1(open(public_key_name, "rb").read())
            self.server_private_key = rsa.PrivateKey.load_pkcs1(open(private_key_name, "rb").read())
        else:
            self.server_public_key, self.server_private_key = rsa.newkeys(2048)
            open(public_key_name, "wb").write(self.server_public_key.save_pkcs1('PEM'))
            open(private_key_name, "wb").write(self.server_private_key.save_pkcs1('PEM'))

    def decrypt_msg(self, msg=None):
        try:
            msg = rsa.decrypt(msg, self.server_private_key)
            return msg
        except Exception as e:
            print("Failure occurred: {}".format(e))


class Client:
    def __init__(self):
        self.client_private_key = None
        self.client_public_key = None
        self.server_public_key = None
        self.encryptor = None
        self.password = None
        self.socket = None
        self.host = None
        self.data = ""
        self.name = ""

    # Connect to server
    def connect_server(self, host, password):
        self.host = host
        self.password = hashlib.sha3_224(password.encode()).digest()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('connecting to %s port %s' % (host, 42328))
        self.socket.connect((host, 42328))

    # Set up encryption
    def encryption_setup(self, server_public_key_name, client_public_key_name,
                         client_private_key_name):  # Load public and private key
        if not os.path.exists(server_public_key_name):
            exit("You need the server public key to connect.")
        else:
            self.server_public_key = rsa.PublicKey.load_pkcs1(open(server_public_key_name, "rb").read())
        if os.path.exists(client_public_key_name) and os.path.exists(client_private_key_name):
            self.client_public_key = rsa.PublicKey.load_pkcs1(open(client_public_key_name, "rb").read())
            self.client_private_key = rsa.PrivateKey.load_pkcs1(open(client_private_key_name, "rb").read())
        else:
            self.client_public_key, self.client_private_key = rsa.newkeys(2048)
            open(client_public_key_name, "wb").write(self.client_public_key.save_pkcs1('PEM'))
            open(client_private_key_name, "wb").write(self.client_private_key.save_pkcs1('PEM'))

    def encrypt_msg(self, msg=None):
        msg = rsa.encrypt(msg, self.server_public_key)
        return msg

    def encrypt_and_send_msg(self, msg=None):
        self.socket.sendall(self.encrypt_msg(msg=self.password) + self.encryptor.encrypt(msg))

    def receive_and_decrypt_msg_response(self):
        return self.encryptor.decrypt(self.socket.recv(16384))

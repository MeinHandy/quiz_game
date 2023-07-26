import reyvotLib as rv
from reyvotLib import *


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
        print('connecting to %s port %s' % (host[0], host[1]))
        self.socket.connect((host[0], host[1]))

    # Set up encryption
    def encryption_setup(self):  # Load public and private key
        if not os.path.exists("server_public_key"):
            exit("You need the server public key to connect.")
        else:
            self.server_public_key = rsa.PublicKey.load_pkcs1(open("server_public_key", "rb").read())
        if os.path.exists("client_public_key") and os.path.exists("client_private_key"):
            self.client_public_key = rsa.PublicKey.load_pkcs1(open("client_public_key", "rb").read())
            self.client_private_key = rsa.PrivateKey.load_pkcs1(open("client_private_key", "rb").read())
        else:
            self.client_public_key, self.client_private_key = rsa.newkeys(2048)
            open("client_public_key", "wb").write(self.client_public_key.save_pkcs1('PEM'))
            open("client_private_key", "wb").write(self.client_private_key.save_pkcs1('PEM'))

    def encrypt_msg(self, msg=None):
        msg = rsa.encrypt(msg, self.server_public_key)
        return msg

    def encrypt_and_send_msg(self, msg=None):
        self.socket.sendall(self.encrypt_msg(msg=self.password) + self.encryptor.encrypt(msg))

    def receive_and_decrypt_msg_response(self):
        return self.encryptor.decrypt(self.socket.recv(16384))


class Game:
    def __init__(self):
        self.server_ip = None
        self.server_port = None

    def join_game(self):
        self.server_ip = "localhost"
        self.server_port = 34197
        client.encryption_setup()
        client.connect_server(host=(self.server_ip, self.server_port), password="joe")
        client.encryptor = AESCipher(str(client.password))


if __name__ == '__main__':
    client = Client()
    game = Game()
    game.join_game()
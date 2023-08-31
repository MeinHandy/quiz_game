from Crypto.Cipher import AES
from Crypto import Random
import threading
import hashlib
import socket
import base64
import time
import rsa
import os
import json
import ast


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
    def encryption_setup(self):  # Load public and private key
        if os.path.exists("server_public_key") and os.path.exists("server_private_key"):
            self.server_public_key = rsa.PublicKey.load_pkcs1(open("server_public_key", "rb").read())
            self.server_private_key = rsa.PrivateKey.load_pkcs1(open("server_private_key", "rb").read())
        else:
            self.server_public_key, self.server_private_key = rsa.newkeys(2048)
            open("server_public_key", "wb").write(self.server_public_key.save_pkcs1('PEM'))
            open("server_private_key", "wb").write(self.server_private_key.save_pkcs1('PEM'))

    def decrypt_msg(self, msg=None):
        try:
            msg = rsa.decrypt(msg, self.server_private_key)
            return msg
        except Exception as e:
            print("Failure occurred: {}".format(e))


# My code
class Game:
    def __init__(self):
        if os.path.exists("quizlist"):  # checks if a quizlist already exists
            print("Reading quiz data, please wait...")
            with open('quizlist') as quizlist:
                data = quizlist.read()
                self.quiz_list = json.loads(data)
        else:  # loads a default quiz list and saves it as a file
            print("Creating list, please wait...")
            self.quiz_list = {
                "Addition": {"10+10": [20, 99, 98, 97], "10+15": [25, 99, 98, 97], "20+20": [40, 99, 98, 97]},
                "Multiplication": {"5*10": [50, 1, 2, 3], "10*10": [100, 1, 2, 3]},
                "Subtraction": {"20-10": [10, 99, 98, 97], "30-15": [15, 99, 98, 97]},
                "The alphabet": {"What is the first letter of the alphabet?": ['a', 'b', 'c', 'd'],
                                 "What is the last letter of the alphabet?": ['z', 'y', 'x', 'w']}
                }
            with open('quizlist', "x") as quizlist:
                json.dump(self.quiz_list, quizlist)

    def process_request(self, msg, username):

        response = ""
        # for item in range(len(command_chain)):  # Start processing command_chain here
        if msg == "quiz_list":
            response += str(self.quiz_list) + ','
        elif msg[0] == "$":  # an identifier to see if the first letter is a dollar sign, designated for new quizzes
            msg = msg[1:]  # remove the dollar sign
            msg = ast.literal_eval(msg)  # converts the string (o.o)
            quiz_name = list(msg.keys())[0]
            self.quiz_list[quiz_name] = msg[quiz_name]
            response = "Quiz submitted"
        return response  # What client sees


class ServerThread(threading.Thread):
    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.password = None  # User password
        self.encryptor = None  # Encryption object
        self.response = None  # response from server to user
        self.msg = None
        self.timeout = 10  # seconds of not receiving any messages to time out after
        self.counter = 0
        print("[+] New thread started for " + self.ip + ":" + str(self.port))

    def run(self):
        print("Connection from : " + self.ip + ":" + str(self.port))
        while True:
            try:
                # Receive and expire if dead
                self.msg = serversock.recv(16384)
                if self.msg == b'':
                    self.counter += 0.2
                    time.sleep(0.2)
                    if self.counter >= self.timeout:
                        break
                    continue

                self.password = server.decrypt_msg(self.msg[0:256])
                self.encryptor = AESCipher(str(self.password))
                self.msg = self.encryptor.decrypt(self.msg[256:])

                print('received "%s"' % self.msg)
                print("Processing request")
                self.response = game.process_request(self.msg, self.password)

                # Response
                print('sending data back to the client')
                serversock.sendall(self.encryptor.encrypt(self.response))  # Pass str into encryptor
                self.counter = 0
            except Exception as e:
                print("Failure occurred: {}".format(e))
        print("[-] Client disconnected...")
        print("[-] Thread stopped for " + self.ip + ":" + str(self.port))


if __name__ == '__main__':
    server = Server()
    server.encryption_setup()
    game = Game()

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tcpsock.bind(('localhost', 34197))
    threads = []
    while True:
        tcpsock.listen(4)
        print("\nListening for incoming connections...")
        (serversock, (ip, port)) = tcpsock.accept()
        newthread = ServerThread(ip, port)
        newthread.start()
        threads.append(newthread)

    for t in threads:
        t.join()

import threading
import reyvotLib as rv
from reyvotLib import *


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
                # Do shit here
                # self.response = game.process_request(self.msg, self.password)

                # Response
                print('sending data back to the client')
                serversock.sendall(self.encryptor.encrypt(self.response))  # Pass str into encryptor
                self.counter = 0
            except Exception as e:
                print("Failure occurred: {}".format(e))
        print("[-] Client disconnected...")
        print("[-] Thread stopped for " + self.ip + ":" + str(self.port))


if __name__ == '__main__':
    server = rv.Server()
    rv.Server.encryption_setup(server, private_key_name="server_private_key", public_key_name="server_public_key")

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
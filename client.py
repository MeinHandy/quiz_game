from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import socket
import base64
import rsa
#  I'm using the following
import os
from tkinter import *
from tkinter import ttk
import ast
import random
import copy


class AESCipher(object):  # not mine
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


class Client:  # not mine
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


def raw_request(message):  # to bypass process_response
    request = str(message)  # May contain 8192 bytes
    client.encrypt_and_send_msg(request)  # Message
    response = client.receive_and_decrypt_msg_response()  # Response
    return response


def process_response(response):  # not mine part of lib
    command_chain = []
    command = ""
    for letter in response + ',':
        if letter == ',':
            command_chain.append(command)
            command = ""
        else:
            command += letter
    return command_chain


class Game:  # everything in this class was written by andre
    def __init__(self):
        self.valid_question = True
        self.exit_button = None
        self.valid_quiz = False
        self.answer_label = None
        self.next_button = None
        self.answer_button_d = None
        self.answer_button_c = None
        self.answer_button_b = None
        self.answer_button_a = None
        self.answer_list = None
        self.sent_quiz = {}
        self.quiz_name_input = None
        self.question_data = None
        self.new_quiz = {}
        self.finish_button = None
        self.add_question_button = None
        self.question_input = None
        self.add_question = None
        self.wrong_answer_c = None
        self.wrong_answer_b = None
        self.wrong_answer_a = None
        self.fake_answer_frame = None
        self.correct_answer = None
        self.correct_frame = None
        self.quiz_name = None
        self.question_input_frame = None
        self.name_frame = None
        self.refresh_quiz = None
        self.create_quiz_button = None
        self.feedback = None
        self.correct = 0
        self.incorrect = 0
        self.quiz_list_constant = None
        self.quiz_frame = None
        self.quiz_data = None
        self.question = None
        self.quiz_questions = None
        self.answer = None
        self.quiz_start_button = None
        self.quiz_list_box = None
        self.selected_quiz = None
        self.quiz_menu_frame = None
        self.menu_frame = None
        self.quiz_list = None
        self.server_list = None
        self.server_ips = {"localhost": 34197, "127.0.0.1": 34197}  # both localhost, but for demonstration purposes
        self.client = None
        self.server_port = None
        self.server_ip = None
        self.buttons = {}
        self.root = Tk()
        self.main_menu()

    def send_request(self, message):
        request = str(message)  # May contain 8192 bytes
        client.encrypt_and_send_msg(request)  # Message
        response = client.receive_and_decrypt_msg_response()  # Response
        command_chain = process_response(response)
        return command_chain

    def main_menu(self):  # sets the menu up
        self.menu_frame = ttk.LabelFrame(self.root, text="game")
        self.menu_frame.grid()
        join_button = ttk.Button(self.menu_frame, text="join", command=self.join_server)
        join_button.grid()
        selected_server = StringVar()
        selected_server.set(list(self.server_ips.keys())[0])
        self.server_list = ttk.Combobox(self.menu_frame, textvariable=selected_server, state="readonly")
        self.server_list['values'] = list(self.server_ips)  # sets the server list up
        self.server_list.grid()
        self.root.mainloop()

    def join_server(self):  # starts connection
        self.server_ip = self.server_list.get()
        self.server_port = self.server_ips.get(self.server_list.get())
        client.encryption_setup()
        client.connect_server(host=(self.server_ip, self.server_port), password="user")  # password is a username
        client.encryptor = AESCipher(str(client.password))
        self.quiz_list_constant = raw_request("quiz_list")  # not running on the function
        self.quiz_list_constant = self.quiz_list_constant[:-1]  # removes annoying comma
        self.quiz_list_constant = ast.literal_eval(self.quiz_list_constant)
        self.quiz_list = copy.deepcopy(self.quiz_list_constant)  # updates the flexible self.quiz_list
        self.menu_frame.destroy()  # destroys the menu so the new ui can be displayed
        self.quiz_menu()

    def quiz_request(self):  # allows for quick request/refresh of server list
        self.quiz_list_constant = raw_request("quiz_list")
        self.quiz_list_constant = self.quiz_list_constant[:-1]  # removes annoying comma
        self.quiz_list_constant = ast.literal_eval(self.quiz_list_constant)
        self.quiz_list = copy.deepcopy(self.quiz_list_constant)  # updates the flexible self.quiz_list
        self.quiz_list_box['values'] = list(self.quiz_list)  # updates the quiz list box to newest data

    def quiz_menu(self):  # sets menu up
        self.quiz_list = copy.deepcopy(self.quiz_list_constant)  # resets the list
        self.quiz_menu_frame = ttk.LabelFrame(self.root)  # menu frame to store everything
        self.quiz_menu_frame.grid()
        self.selected_quiz = StringVar()  # variable to access combobox
        self.selected_quiz.set(list(self.quiz_list.keys())[0])
        self.quiz_list_box = ttk.Combobox(self.quiz_menu_frame, textvariable=self.selected_quiz, state="readonly")
        self.quiz_list_box['values'] = list(self.quiz_list)
        self.quiz_list_box.grid()  # all just button setups
        self.quiz_start_button = ttk.Button(self.quiz_menu_frame, text="Start Quiz", command=self.quiz_start)
        self.quiz_start_button.grid()
        self.refresh_quiz = ttk.Button(self.quiz_menu_frame, text="Refresh list", command=self.quiz_request)
        self.refresh_quiz.grid()
        self.create_quiz_button = ttk.Button(self.quiz_menu_frame, text="Create a quiz", command=self.quiz_creator)
        self.create_quiz_button.grid(pady=20)

    def quiz_start(self):  # starts the quiz and sets data up
        self.correct = 0
        self.incorrect = 0
        self.selected_quiz = self.quiz_list_box.get()
        self.quiz_menu_frame.destroy()
        self.quiz_data = self.quiz_list[self.selected_quiz]
        self.quiz_questions = list(self.quiz_data.keys())
        random.shuffle(self.quiz_questions)
        self.next_question()

    def next_question(self):  # moves to next question, is also first question
        self.question = self.quiz_questions[random.randint(0, len(self.quiz_questions) - 1)]  # picks a random question
        self.answer = self.quiz_data[self.question][0]  # answer
        possible_answers = self.quiz_data[self.question]
        random.shuffle(possible_answers)
        answer_a = possible_answers[0]  # sets the buttons to the randomized list, hardcoded because only 4 questions
        answer_b = possible_answers[1]  # possible
        answer_c = possible_answers[2]
        answer_d = possible_answers[3]

        self.quiz_frame = ttk.LabelFrame(self.root, text=self.selected_quiz)
        self.quiz_frame.grid()
        quiz_question = Label(self.quiz_frame, text=self.question)
        quiz_question.grid(row=0, column=0, columnspan=3)
        self.answer_button_a = ttk.Button(self.quiz_frame, text=answer_a,  # sets up all the answer buttons
                                          command=lambda response=answer_a: self.check_answer(response))
        self.answer_button_a.grid(row=1, column=1)
        self.answer_button_b = ttk.Button(self.quiz_frame, text=answer_b,
                                          command=lambda response=answer_b: self.check_answer(response))
        self.answer_button_b.grid(row=1, column=2)
        self.answer_button_c = ttk.Button(self.quiz_frame, text=answer_c,
                                          command=lambda response=answer_c: self.check_answer(response))
        self.answer_button_c.grid(row=2, column=1)
        self.answer_button_d = ttk.Button(self.quiz_frame, text=answer_d,
                                          command=lambda response=answer_d: self.check_answer(response))
        self.answer_button_d.grid(row=2, column=2)
        self.answer_label = Label(self.quiz_frame, text="")
        self.answer_label.grid(row=3, column=0, columnspan=3)
        self.next_button = ttk.Button(self.quiz_frame, text="Next question",
                                      command=self.reset_question, state="disabled")
        self.next_button.grid(row=4, column=0, columnspan=3)

    def check_answer(self, response):
        self.feedback = StringVar()
        if response == self.answer:  # checks if user was correct
            self.quiz_questions.remove(self.question)
            self.correct += 1

        else:
            self.quiz_questions.remove(self.question)
            self.incorrect += 1

        if len(self.quiz_questions) > 0:  # if there are more questions continue
            self.next_button["state"] = "enabled"
            self.answer_label["text"] = "Correct answer: {}".format(self.answer)
            self.answer_button_a["state"] = "disabled"  # disables the answer buttons.
            self.answer_button_b["state"] = "disabled"
            self.answer_button_c["state"] = "disabled"
            self.answer_button_d["state"] = "disabled"

        else:
            self.answer_button_a["state"] = "disabled"
            self.answer_button_b["state"] = "disabled"
            self.answer_button_c["state"] = "disabled"
            self.answer_button_d["state"] = "disabled"
            self.end_quiz()

    def reset_question(self):
        self.quiz_frame.destroy()
        self.next_question()

    def end_quiz(self):
        self.answer_label["text"] = "Correct answer: {}".format(self.answer)
        self.next_button["state"] = "enabled"
        self.next_button["text"] = "End Quiz"
        self.next_button["command"] = self.post_quiz

    def post_quiz(self):
        self.quiz_frame.destroy()
        self.quiz_menu()

    def quiz_creator(self):
        self.quiz_menu_frame.destroy()

        self.name_frame = ttk.LabelFrame(self.root, text="Quiz Name")  # quiz name input field
        self.name_frame.grid()
        self.quiz_name_input = Entry(self.name_frame)
        self.quiz_name_input.grid()

        self.question_input_frame = ttk.LabelFrame(self.root, text="Question")  # question input field
        self.question_input_frame.grid()
        self.question_input = Entry(self.question_input_frame)
        self.question_input.grid()

        self.correct_frame = ttk.LabelFrame(self.root, text="Correct answer")  # correct answer input
        self.correct_frame.grid()
        self.correct_answer = Entry(self.correct_frame)
        self.correct_answer.grid()

        self.fake_answer_frame = ttk.LabelFrame(self.root, text="Incorrect answers")
        self.fake_answer_frame.grid()
        self.wrong_answer_a = Entry(self.fake_answer_frame)  # inits the entry boxes
        self.wrong_answer_a.grid()
        self.wrong_answer_b = Entry(self.fake_answer_frame)
        self.wrong_answer_b.grid()
        self.wrong_answer_c = Entry(self.fake_answer_frame)
        self.wrong_answer_c.grid()

        self.add_question_button = ttk.Button(self.root, text="Add question", command=self.add_question_func)  # add q
        self.add_question_button.grid()

        self.finish_button = ttk.Button(self.root, text="Finished", state="disabled",
                                        command=self.finished_new_quiz)  # finished button
        self.finish_button.grid()
        self.exit_button = ttk.Button(self.root, text="Exit without saving", command=self.exit_without_saving)
        self.exit_button.grid()

    def add_question_func(self):
        self.quiz_name = self.quiz_name_input.get()
        if self.quiz_name in self.quiz_list_constant.keys():  # checks if quiz already exists
            self.quiz_name_input.configure(bg="red")
            self.valid_question = False
        elif self.quiz_name_input.get().strip() != "":
            self.quiz_name_input.configure(bg="white")

        if self.quiz_name.strip() == "":  # enforces valid input.
            self.quiz_name_input.configure(bg="red")
            self.valid_question = False
        elif self.quiz_name.strip() != "":  # else could be used here, but under pretext of expansion,
            self.quiz_name_input.configure(bg="white")  # elifs are used

        if self.question_input.get().strip() == "":  # checks if empty
            self.question_input.configure(bg="red")
            self.valid_question = False  # question is invalid
        elif self.question_input.get().strip() != "":
            self.question_input.configure(bg="white")

        if self.correct_answer.get().strip() == "":
            self.correct_answer.configure(bg="red")
            self.valid_question = False
        elif self.correct_answer.get().strip() != "":
            self.correct_answer.configure(bg="white")

        if self.wrong_answer_a.get().strip() == "":
            self.wrong_answer_a.configure(bg="red")
            self.valid_question = False
        elif self.wrong_answer_a.get().strip() != "":
            self.wrong_answer_a.configure(bg="white")

        if self.wrong_answer_b.get().strip() == "":
            self.wrong_answer_b.configure(bg="red")
            self.valid_question = False
        elif self.wrong_answer_b.get().strip() != "":
            self.wrong_answer_b.configure(bg="white")

        if self.wrong_answer_c.get().strip() == "":
            self.wrong_answer_c.configure(bg="red")
            self.valid_question = False
        elif self.wrong_answer_c.get().strip() != "":
            self.wrong_answer_c.configure(bg="white")

        if self.valid_question:
            self.quiz_name_input.config(state="disabled")
            self.finish_button.config(state="enabled")
            self.answer_list = [self.correct_answer.get(), self.wrong_answer_a.get(),  # sets the answer list up
                                self.wrong_answer_b.get(), self.wrong_answer_c.get()]
            self.question = self.question_input.get()
            self.question_data = {self.question: self.answer_list}  # binds the question to the answers
            self.sent_quiz.setdefault(self.quiz_name, {}).update(self.question_data)
            self.valid_quiz = True
        else:  # assumes question is valid, on button press will retest validity
            self.valid_question = True

    def finished_new_quiz(self):
        if self.valid_quiz:  # checks if the quiz contains data
            self.name_frame.destroy()  # just clears the creation box
            self.question_input_frame.destroy()
            self.correct_frame.destroy()
            self.fake_answer_frame.destroy()
            self.add_question_button.destroy()
            self.finish_button.destroy()
            self.exit_button.destroy()
            compiled_quiz = "$" + str(self.sent_quiz)  # formats the quiz for sending
            self.send_request(compiled_quiz)  # uses send request (used as just send)
            self.answer_list = []
            self.question = ""
            self.question_data = {}
            self.sent_quiz = {}
            self.valid_quiz = False
            self.quiz_menu()  # loops back to the main menu
    
    def exit_without_saving(self):
        self.name_frame.destroy()  # just clears the creation box
        self.question_input_frame.destroy()
        self.correct_frame.destroy()
        self.fake_answer_frame.destroy()
        self.add_question_button.destroy()
        self.finish_button.destroy()
        self.answer_list = []
        self.question = ""
        self.question_data = {}
        self.sent_quiz = {}
        self.valid_quiz = False
        self.exit_button.destroy()
        self.quiz_menu()  # loops back to the main menu   


if __name__ == '__main__':
    client = Client()
    game = Game()

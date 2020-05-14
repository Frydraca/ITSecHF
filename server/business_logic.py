import json
from Crypto.Hash import SHA256, SHA3_256
from session import Session
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import PBKDF2
from datetime import datetime
import os

class BLL:

    def __init__(self, signer, password):
        self.signer = signer
        self.session_store = dict()
        self.logged_in_session = None

        self.password = password
        self.users = dict()
        self.decrypt_users()
        print()
        print("Users: ")
        print(json.dumps(list(self.users.keys()), indent=2))


    def create_timestamp(self):
        now = datetime.now()
        return datetime.timestamp(now)


    def encrypt_users(self):
        data = json.dumps(self.users).encode('utf-8')
        file_out = open("users.bin", "wb")

        salt = get_random_bytes(16)
        key = PBKDF2(self.password, salt, 16, count=10000, hmac_hash_module=SHA256)

        cipher_aes = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (salt, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()


    def decrypt_users(self):
        try:
            file_in = open("users.bin", "rb")
            
            salt, nonce, tag, ciphertext = \
                [ file_in.read(x) for x in (16, 16, 16, -1) ]
            key = PBKDF2(self.password, salt, 16, count=10000, hmac_hash_module=SHA256)

            cipher_aes = AES.new(key, AES.MODE_EAX, nonce)
            users = cipher_aes.decrypt_and_verify(ciphertext, tag)
            self.users = json.loads(users.decode("utf-8"))
        except FileNotFoundError:
            self.encrypt_users()


    def basic_validate_message(self, msg_obj: dict) -> bool:
        return "client_id" in msg_obj.keys() and \
               "data" in msg_obj.keys() and \
               "type" in msg_obj["data"].keys()


    def validate_ini(self, msg_obj: dict) -> bool:
        return msg_obj["client_id"] not in self.session_store.keys() and \
               "pub_key" in msg_obj["data"].keys() and \
               "pub_curve_key" in msg_obj["data"].keys()


    def encode_message(self, message, client_id) -> bytes:
        # Signing 
        hashed_message = SHA256.new(json.dumps(message).encode('utf-8'))
        signature = self.signer.sign(hashed_message)

        messageToEncodeBytes = signature + json.dumps(message).encode("utf-8")

        # Encrypt
        message_key = get_random_bytes(16)
        clientPublicKey = RSA.import_key(self.session_store[client_id].clientPubKey)

        cipher_rsa = PKCS1_OAEP.new(clientPublicKey)
        encodedMessageKey = cipher_rsa.encrypt(message_key)
        cipher_aes = AES.new(message_key, AES.MODE_EAX)
        encodedMessage, tag = cipher_aes.encrypt_and_digest(messageToEncodeBytes)

        resultMessage = encodedMessageKey + \
                        cipher_aes.nonce + \
                        tag + \
                        encodedMessage

        return resultMessage


    def validate_user(self, msg_obj: dict) -> bool:
        return "username" in msg_obj["data"].keys() and \
               "password" in msg_obj["data"].keys()


    def validate_command(self, msg_obj: dict) -> bool:
        return self.logged_in_session == msg_obj["client_id"]


    def validate_signature(self, client_id: str, byte_msg: bytes, signature: bytes) -> bool:
        client_curve_key = ECC.import_key(self.session_store[client_id].clientCurvePubKey)
        h = SHA256.new(byte_msg)
        verifier = DSS.new(client_curve_key, 'fips-186-3')

        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


    def resolve_message(self, byte_msg: bytes, signature: bytes) -> bytes:
        msg = byte_msg.decode('utf-8')
        msg_obj = json.loads(msg)
        if self.basic_validate_message(msg_obj):
            print()
            print("Incoming message:")
            print(json.dumps(msg_obj, indent=2))

            if msg_obj["data"]["type"] == "INI":
                if self.validate_ini(msg_obj):
                    return self.INI(msg_obj)

            elif "client_id" in msg_obj.keys() and \
                 msg_obj["client_id"] in self.session_store.keys() and \
                 self.validate_signature(msg_obj["client_id"], byte_msg, signature): 
                    if msg_obj["data"]["type"] == "REG":
                        if self.validate_user(msg_obj) and msg_obj["data"]["username"] not in self.users.keys():
                            response = self.REG(msg_obj)
                            del self.session_store[msg_obj["client_id"]] 
                            return response
                        else:
                            response = self.encode_message({"response": "Cannot create user!"}, msg_obj["client_id"])
                            del self.session_store[msg_obj["client_id"]]
                            return response

                    elif msg_obj["data"]["type"] == "LIN":
                        if self.validate_user(msg_obj) and \
                                msg_obj["data"]["username"] in self.users.keys() and \
                                self.logged_in_session == None:
                            return self.LIN(msg_obj)
                        else:
                            return self.encode_message({"timestamp": self.create_timestamp(), \
                                        "response": "Failed login!"}, msg_obj["client_id"])
                            
                    elif msg_obj["data"]["type"] == "MKD":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "RMD":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "CWD":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "UPL":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "DNL":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "LST":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "RMF":
                        if self.validate_command(msg_obj):
                            return self.GWD(msg_obj)
                    elif msg_obj["data"]["type"] == "GWD":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "EXT":
                        if self.validate_command(msg_obj):
                            return self.EXT(msg_obj)
                

            if msg_obj["client_id"] in self.session_store.keys():
                #Error handling
                return self.encode_message({"response": "Server side error"}, msg_obj["client_id"])
            

        return b"Fundamentaly Bad Message!"


    def INI(self, msg_obj: dict) -> bytes:
        newSession = Session()
        newSession.clientId = msg_obj["client_id"]
        newSession.clientPubKey = msg_obj["data"]["pub_key"]
        newSession.clientCurvePubKey = msg_obj["data"]["pub_curve_key"]

        self.session_store.update({msg_obj["client_id"] : newSession})
        print()
        print("Sessions stored: {}".format(len(self.session_store.keys())))
        return self.encode_message({"response": "ack"}, newSession.clientId)


    def REG(self, msg_obj: dict) -> bytes:
        h_obj = SHA3_256.new()
        h_obj.update(msg_obj["data"]["password"].encode("utf-8"))
        hashed_password = h_obj.hexdigest()
        
        self.users.update({msg_obj["data"]["username"] : hashed_password})
        self.encrypt_users()

        os.makedirs("users/{}".format(msg_obj["data"]["username"]))
        return self.encode_message({"response": "User successfully created!"}, msg_obj["client_id"])


    def LIN(self, msg_obj: dict) -> bytes:
        h_obj = SHA3_256.new()
        h_obj.update(msg_obj["data"]["password"].encode("utf-8"))
        hashed_password = h_obj.hexdigest()

        if self.users[msg_obj["data"]["username"]] == hashed_password:
            self.session_store[msg_obj["client_id"]].user = msg_obj["data"]["username"]
            self.session_store[msg_obj["client_id"]].password = msg_obj["data"]["password"]
            self.logged_in_session = msg_obj["client_id"]

            return self.encode_message({"timestamp": self.create_timestamp(), \
                                        "response": "Successfull login!"}, msg_obj["client_id"])
        else:
            return self.encode_message({"timestamp": self.create_timestamp(), \
                                        "response": "Failed login!"}, msg_obj["client_id"])


    def GWD(self, msg_obj: dict) -> bytes:
        if os.path.isdir("./users/{}".format(msg_obj["data"]["username"])):
            self.session_store[self.logged_in_session].path = msg_obj["data"]["username"]
            return self.encode_message({"type": msg_obj["data"]["type"], \
                                        "seq_id": 1,\
                                        "timestamp": self.create_timestamp(), \
                                        "response": self.session_store[self.logged_in_session].path}, \
                                        msg_obj["client_id"])
        else:
            self.EXT(msg_obj)
            return self.encode_message({"type": msg_obj["data"]["type"], \
                                        "seq_id": 1,\
                                        "timestamp": self.create_timestamp(), \
                                        "response": { "error" : "No directory for the user!"}
                                        }, \
                                        msg_obj["client_id"])


    def EXT(self, msg_obj: dict) -> bytes:
        del self.session_store[self.logged_in_session]
        self.logged_in_session = ''
        return self.encode_message({"type": msg_obj["data"]["type"], \
                                        "seq_id": 1,\
                                        "timestamp": self.create_timestamp(), \
                                        "response": "Logged out!"
                                        }, \
                                        msg_obj["client_id"])
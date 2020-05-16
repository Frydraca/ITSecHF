import json
from Crypto.Hash import SHA256, SHA3_256
from session import Session
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import PBKDF2
from datetime import datetime
import shutil
import os
import io

class BLL:

    def __init__(self, signer, password):
        self.signer = signer
        self.session_store = dict()
        self.logged_in_session = None
        self.waiting_for_upload = None

        self.password = password
        self.users = dict()
        self.decrypt_users()
        print()
        print("Users: ")
        print(json.dumps(list(self.users.keys()), indent=2))


    def create_timestamp(self):
        now = datetime.now()
        return datetime.timestamp(now)


    def concat_and_normalize_path(self, added_path):
        rootPath = "users/{}".format(self.session_store[self.logged_in_session].user)
        actPath = rootPath + self.session_store[self.logged_in_session].path
        newPath = actPath + added_path
        return os.path.normpath(newPath)


    def create_cmd_response(self,msg_obj,response):
        return {"type": msg_obj["data"]["type"], \
                "seq_id": self.session_store[self.logged_in_session].seq_id,\
                "timestamp": self.create_timestamp(), \
                "response": response}


    def encrypt_users(self):
        data = json.dumps(self.users).encode('utf-8')
        file_out = open("users.bin", "wb")

        salt = get_random_bytes(16)
        key = PBKDF2(self.password, salt, 16, count=100000, hmac_hash_module=SHA256)

        cipher_aes = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (salt, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()


    def decrypt_users(self):
        try:
            file_in = open("users.bin", "rb")
            
            salt, nonce, tag, ciphertext = \
                [ file_in.read(x) for x in (16, 16, 16, -1) ]
            key = PBKDF2(self.password, salt, 16, count=100000, hmac_hash_module=SHA256)

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


    def sign_message(self, message_bytes: bytes) -> bytes:
        hashed_message = SHA256.new(message_bytes)
        signature = self.signer.sign(hashed_message)

        return signature + message_bytes


    def encode_message(self, message, client_id) -> bytes:
        # Signing        
        messageToEncodeBytes = self.sign_message(message)

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

    def encode_message_json(self, jmessage, client_id) -> bytes:
        return self.encode_message(json.dumps(jmessage).encode('utf-8'), client_id)


    def encode_message_json_and_file(self, jmessage, file, client_id) -> bytes:
        return self.encode_message(file + json.dumps(jmessage).encode('utf-8'), client_id)


    def validate_user(self, msg_obj: dict) -> bool:
        return "username" in msg_obj["data"].keys() and \
               "password" in msg_obj["data"].keys()


    def validate_timestamp(self, data: dict) -> bool:
        if "timestamp" in data.keys():
            serverTime = datetime.now()
            clientTime = datetime.fromtimestamp(data["timestamp"])
            return serverTime > clientTime and \
                   (serverTime - clientTime).total_seconds() < 5
        else:
            return False


    def validate_and_update_seq(self, data: dict) -> bool:
        if "seq_id" in data.keys() and \
            data["seq_id"] == self.session_store[self.logged_in_session].seq_id + 1:
            self.session_store[self.logged_in_session].seq_id = data["seq_id"] + 1
            return True
        else:
            return False 


    def validate_command(self, msg_obj: dict) -> bool:
        return self.validate_timestamp(msg_obj["data"]) and \
               self.logged_in_session == msg_obj["client_id"] and \
               self.validate_and_update_seq(msg_obj["data"])


    def validate_signature(self, client_id: str, byte_msg: bytes, signature: bytes) -> bool:
        client_curve_key = ECC.import_key(self.session_store[client_id].clientCurvePubKey)
        h = SHA256.new(byte_msg)
        verifier = DSS.new(client_curve_key, 'fips-186-3')

        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


    def normal_msg_parse(self,byte_msg: bytes) -> dict:
        msg = byte_msg.decode('utf-8')
        return json.loads(msg)


    def file_and_msg_parse(self,byte_msg: bytes) -> tuple:
        f = io.BytesIO(byte_msg)
        file, msg = \
            [ f.read(x) for x in (self.waiting_for_upload["size"], -1) ]
        f.close()
        return file, self.normal_msg_parse(msg)

    ################################# RESOLVES INCOMMING MESAGES ##################################
    def resolve_message(self, byte_msg: bytes, signature: bytes) -> list:
        if self.waiting_for_upload == None:
            msg_obj = self.normal_msg_parse(byte_msg)
        else:
            file, msg_obj = self.file_and_msg_parse(byte_msg)

        if self.basic_validate_message(msg_obj):
            print()
            print("Incoming message:")
            print(json.dumps(msg_obj, indent=2))

            if msg_obj["data"]["type"] == "INI":
                if self.validate_ini(msg_obj):
                    return [self.INI(msg_obj)]

            elif "client_id" in msg_obj.keys() and \
                 msg_obj["client_id"] in self.session_store.keys() and \
                 self.validate_signature(msg_obj["client_id"], byte_msg, signature): 
                    if self.waiting_for_upload == None:
                        if msg_obj["data"]["type"] == "REG":
                            if self.validate_user(msg_obj) and msg_obj["data"]["username"] not in self.users.keys():
                                response = self.REG(msg_obj)
                                del self.session_store[msg_obj["client_id"]] 
                                return [response]
                            else:
                                response = self.encode_message_json({"response": { "error" : "Cannot create user!"}}, msg_obj["client_id"])
                                del self.session_store[msg_obj["client_id"]]
                                return [response]

                        elif msg_obj["data"]["type"] == "LIN":
                            if self.validate_user(msg_obj) and \
                                    msg_obj["data"]["username"] in self.users.keys() and \
                                    self.validate_timestamp(msg_obj["data"]) and \
                                    self.logged_in_session == None:
                                return [self.LIN(msg_obj)]
                            else:
                                response = self.encode_message_json({"timestamp": self.create_timestamp(), \
                                            "response": { "error" : "Failed login!"}}, msg_obj["client_id"])
                                del self.session_store[msg_obj["client_id"]]
                                self.logged_in_session = None
                                self.waiting_for_upload = None
                                return [response]
                                
                        elif msg_obj["data"]["type"] == "MKD":
                            if self.validate_command(msg_obj):
                                return [self.MKD(msg_obj)]

                        elif msg_obj["data"]["type"] == "RMD":
                            if self.validate_command(msg_obj):
                                return [self.RMD(msg_obj)]

                        elif msg_obj["data"]["type"] == "CWD":
                            if self.validate_command(msg_obj):
                                return [self.CWD(msg_obj)]

                        elif msg_obj["data"]["type"] == "UPL":
                            if self.validate_command(msg_obj):
                                return [self.UPL(msg_obj)]

                        elif msg_obj["data"]["type"] == "DNL":
                            if self.validate_command(msg_obj):
                                success, download_response = self.DNL(msg_obj)
                                if success:
                                    sending_file = self.Send_File(msg_obj)
                                    return [download_response, sending_file]
                                else:
                                    return [download_response]
                        
                        elif msg_obj["data"]["type"] == "LST":
                            if self.validate_command(msg_obj):
                                return [self.LST(msg_obj)]

                        elif msg_obj["data"]["type"] == "RMF":
                            if self.validate_command(msg_obj):
                                return [self.RMF(msg_obj)]

                        elif msg_obj["data"]["type"] == "GWD":
                            if self.validate_command(msg_obj):
                                return [self.GWD(msg_obj)]
                                
                        elif msg_obj["data"]["type"] == "EXT":
                            if self.validate_command(msg_obj):
                                return [self.EXT(msg_obj)]
                    else:
                        if msg_obj["data"]["type"] == "SVU":
                            if self.validate_command(msg_obj):
                                response = self.SVU(msg_obj, file)
                                return [response]
                        self.waiting_for_upload = None

            if msg_obj["client_id"] in self.session_store.keys():
                #Error handling
                return [self.encode_message_json({"response": { "error" : "Server side error" } }, msg_obj["client_id"])]
            

        return [b"Fundamentaly Bad Message!"]


    ##################################### RESOLVE COMMANDS ########################################
    def INI(self, msg_obj: dict) -> bytes:
        newSession = Session()
        newSession.clientId = msg_obj["client_id"]
        newSession.clientPubKey = msg_obj["data"]["pub_key"]
        newSession.clientCurvePubKey = msg_obj["data"]["pub_curve_key"]

        self.session_store.update({msg_obj["client_id"] : newSession})
        print()
        print("Sessions stored: {}".format(len(self.session_store.keys())))
        return self.encode_message_json({"response": "ack"}, newSession.clientId)


    def REG(self, msg_obj: dict) -> bytes:
        h_obj = SHA3_256.new()
        h_obj.update(msg_obj["data"]["password"].encode("utf-8"))
        hashed_password = h_obj.hexdigest()
        
        self.users.update({msg_obj["data"]["username"] : hashed_password})
        self.encrypt_users()

        os.makedirs("users/{}".format(msg_obj["data"]["username"]))
        return self.encode_message_json({"response": "User successfully created!"}, msg_obj["client_id"])


    def LIN(self, msg_obj: dict) -> bytes:
        h_obj = SHA3_256.new()
        h_obj.update(msg_obj["data"]["password"].encode("utf-8"))
        hashed_password = h_obj.hexdigest()

        if self.users[msg_obj["data"]["username"]] == hashed_password:
            self.session_store[msg_obj["client_id"]].user = msg_obj["data"]["username"]
            self.session_store[msg_obj["client_id"]].password = msg_obj["data"]["password"]
            self.logged_in_session = msg_obj["client_id"]

            return self.encode_message_json({"timestamp": self.create_timestamp(), \
                                        "response": "Successful login!"}, msg_obj["client_id"])
        else:
            response = self.encode_message_json({"timestamp": self.create_timestamp(), \
                                        "response": { "error" : "Failed login!" }}, msg_obj["client_id"])
            del self.session_store[msg_obj["client_id"]]
            self.logged_in_session = None
            self.waiting_for_upload = None
            return response


    def MKD(self, msg_obj: dict) -> bytes:
        rootPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user)) + "\\"
        newPath = self.concat_and_normalize_path(msg_obj["data"]["dir_name"])
        try:
            if newPath.find(rootPath) != 0:
                raise Exception()
            
            os.makedirs(newPath)
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj,"Directory successfully created"), \
                msg_obj["client_id"])
        except:
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj,{ "error" : "Cannot create directory!"}), \
                msg_obj["client_id"])


    def RMD(self, msg_obj: dict) -> bytes:
        actPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user + \
            self.session_store[self.logged_in_session].path)) + "\\"
        newPath = self.concat_and_normalize_path(msg_obj["data"]["dir_name"])
        try:
            if newPath.find(actPath) != 0 or newPath == actPath or not os.path.isdir(newPath):
                raise Exception()
            
            shutil.rmtree(newPath)
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, "Successfully deleted!"), \
                msg_obj["client_id"])
        except:
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, { "error" : "You cannot delete this directory!"}), \
                msg_obj["client_id"])
                

    def CWD(self, msg_obj: dict) -> bytes:
        rootPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user)) + '\\'
        newPath = self.concat_and_normalize_path(msg_obj["data"]["path"]) + '\\'
        try:
            if newPath.find(rootPath) != 0 or not os.path.isdir(newPath):
                raise Exception()
            
            self.session_store[self.logged_in_session].path = newPath[len(rootPath)-1:].replace("\\","/")

            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, self.session_store[self.logged_in_session].path), \
                msg_obj["client_id"])
        except:
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, { "error" : "You cannot change your directory to that!"}), \
                msg_obj["client_id"])


    def UPL(self, msg_obj: dict) -> bytes:
        if os.path.basename(msg_obj["data"]["filename"]) == msg_obj["data"]["filename"]:
            filePath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user + \
                self.session_store[self.logged_in_session].path) + \
                msg_obj["data"]["filename"] )
            
            self.waiting_for_upload = {"path" : filePath, "size" : int(msg_obj["data"]["upload_size"])}
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, "Ready for the upload!"), \
                msg_obj["client_id"])
        else:
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, {"error" : "Cannot upload with this file name!"}), \
                msg_obj["client_id"])


    def SVU(self, msg_obj: dict, file: bytes) -> bytes:
        with open(self.waiting_for_upload["path"], "wb") as file_out:
            file_out.write(file)
        
        self.waiting_for_upload = None
        return self.encode_message_json( \
                self.create_cmd_response(msg_obj, "File successfully saved!"), \
                msg_obj["client_id"])


    def DNL(self, msg_obj: dict) -> tuple:
        rootPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user)) + "\\"
        newPath = self.concat_and_normalize_path(msg_obj["data"]["filename"])
        try:
            if newPath.find(rootPath) != 0 or not os.path.isfile(newPath):
                raise Exception()
            
            return True, self.encode_message_json( \
                self.create_cmd_response(msg_obj, str(os.path.getsize(newPath))), \
                msg_obj["client_id"])
        except:
            return False, self.encode_message_json( \
                self.create_cmd_response(msg_obj, { "error" : "Download failed!"}), \
                msg_obj["client_id"])


    def Send_File(self, msg_obj: dict) -> bytes:
        newPath = self.concat_and_normalize_path(msg_obj["data"]["filename"])
        self.session_store[self.logged_in_session].seq_id += 1

        with open(newPath, "rb") as downloded_file:
            file_bytes = downloded_file.read()
            return self.encode_message_json_and_file( \
                self.create_cmd_response(msg_obj, "Download finished!"), \
                file_bytes, \
                msg_obj["client_id"])
        

    def LST(self, msg_obj: dict) -> bytes:
        actPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user + \
            self.session_store[self.logged_in_session].path))
        
        content = os.listdir(actPath)

        return self.encode_message_json( \
                self.create_cmd_response(msg_obj, content), \
                msg_obj["client_id"])


    def RMF(self, msg_obj: dict) -> bytes:
        actPath = os.path.normpath("users/{}".format(self.session_store[self.logged_in_session].user + \
            self.session_store[self.logged_in_session].path)) + "\\"
        newPath = self.concat_and_normalize_path(msg_obj["data"]["filename"])
        try:
            if newPath.find(actPath) != 0 or newPath == actPath or not os.path.isfile(newPath):
                raise Exception()
            
            os.remove(newPath)
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, "Successfully deleted!"), \
                msg_obj["client_id"])
        except:
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, { "error" : "You cannot delete this file!"}), \
                msg_obj["client_id"])


    def GWD(self, msg_obj: dict) -> bytes:
        if os.path.isdir("./users/{}".format(self.session_store[self.logged_in_session].user)):
            self.session_store[self.logged_in_session].path = "/"
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, self.session_store[self.logged_in_session].path), \
                msg_obj["client_id"])
        else:
            self.EXT(msg_obj)
            return self.encode_message_json( \
                self.create_cmd_response(msg_obj, { "error" : "No directory for the user!"}), \
                msg_obj["client_id"])


    def EXT(self, msg_obj: dict) -> bytes:
        response = self.encode_message_json( \
            self.create_cmd_response(msg_obj, "Logged out!"), \
            msg_obj["client_id"])
        del self.session_store[self.logged_in_session]
        self.logged_in_session = None
        self.waiting_for_upload = None
        return response
import json
from Crypto.Hash import SHA256
from session import Session
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS

class BLL:

    def __init__(self, signer):
        self.signer = signer
        self.session_store = dict()


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
                 self.validate_signature(msg_obj["client_id"], byte_msg, signature): 
                    if msg_obj["data"]["type"] == "REG":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "LIN":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
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
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "GWD":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                    elif msg_obj["data"]["type"] == "EXT":
                        return self.encode_message({"response": "NOT IMPLEMENTED!"}, msg_obj["client_id"])
                

            if msg_obj["client_id"] in self.session_store.keys():
                #Error handling
                return self.encode_message({"response": "Server side error"}, msg_obj["client_id"])
            

        return b"Fundamentaly Bad Message!"


    def INI(self, msg_obj):
        newSession = Session()
        newSession.clientId = msg_obj["client_id"]
        newSession.clientPubKey = msg_obj["data"]["pub_key"]
        newSession.clientCurvePubKey = msg_obj["data"]["pub_curve_key"]

        self.session_store.update({msg_obj["client_id"] : newSession})
        print()
        print("Sessions stored: {}".format(len(self.session_store.keys())))
        return self.encode_message({"response": "ack"}, newSession.clientId)
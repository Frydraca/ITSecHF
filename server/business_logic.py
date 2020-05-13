import json
from Crypto.Hash import SHA256
from session import Session
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

class BLL:

    def __init__(self, signer):
        self.signer = signer
        self.session_store = dict()


    def basic_validate_message(self, msg_obj: dict) -> bool:
        return "client_id" in msg_obj.keys() and "data" in msg_obj.keys() and "type" in msg_obj["data"].keys()


    def validate_ini(self, msg_obj: dict) -> bool:
        return msg_obj["client_id"] not in self.session_store.keys() and "pub_key" in msg_obj["data"].keys() and "pub_curve_key" in msg_obj["data"].keys()


    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')


    def encode_message(self, message, client_id) -> bytes:
        hashed_message = SHA256.new(json.dumps(message).encode('utf-8'))
        signature = self.signer.sign(hashed_message)

        messageToEncode = {
            "data": message,
            "sign": int.from_bytes(signature, 'big')
        }

        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")

        session_key = get_random_bytes(16)
        clientPublicKey = RSA.import_key(self.session_store[client_id].clientPubKey)

        cipher_rsa = PKCS1_OAEP.new(clientPublicKey)
        encodedSessionKey = cipher_rsa.encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        encodedMessage, tag = cipher_aes.encrypt_and_digest(messageToEncodeBytes)

        resultMessage = {
            "enc_session_key": int.from_bytes(encodedSessionKey, 'big'),
            "tag": int.from_bytes(tag, 'big'),
            "nonce": int.from_bytes(cipher_aes.nonce, 'big'),
            "ciphertext": int.from_bytes(encodedMessage, 'big')
        }

        return json.dumps(resultMessage).encode("utf-8")


    def resolve_message(self, byte_msg: bytes) -> bytes:
        msg = byte_msg.decode('utf-8')
        msg_obj = json.loads(msg)
        if self.basic_validate_message(msg_obj):
            print()
            print("Incoming message:")
            print(json.dumps(msg_obj, indent=2))

            if msg_obj["data"]["type"] == "INI":
                if self.validate_ini(msg_obj):
                    newSession = Session()
                    newSession.clientId = msg_obj["client_id"]
                    newSession.clientPubKey = msg_obj["data"]["pub_key"]
                    newSession.clientCurvePubKey = msg_obj["data"]["pub_curve_key"]

                    self.session_store.update({msg_obj["client_id"] : newSession})
                    print()
                    print("Session store updated:")
                    print(json.dumps(list(self.session_store.keys()), indent=2))
                    return self.encode_message("ack", newSession.clientId)
        
        print("Bad Message")

import getpass 
import json
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

class ClientLogic:
    def __init__(self, address):
        self.client_key_public = ''
        self.client_key_private = ''
        self.client_curve_key_public = ''
        self.client_curve_key_private = ''
        self.address = address

        serverPublicKey = RSA.import_key(open("public_server_rsa_key.pem").read())
        self.server_cipher_rsa = PKCS1_OAEP.new(serverPublicKey)


    def int_to_bytes(self, x: int) -> bytes:
        return x.to_bytes((x.bit_length() + 7) // 8, 'big')


    def GetCredentials(self):
        userName = input("Enter your username: ")
        userPassword = getpass.getpass()
        return userName, userPassword


    def GenerateRsaKeys(self):
        client_key = RSA.generate(2048)
        self.client_key_private = client_key.export_key()
        self.client_key_public = client_key.publickey().export_key().decode('utf-8')



    def GenerateSignKey(self):
        key = ECC.generate(curve='P-256')
        self.client_curve_key_private = key.export_key(format='PEM')
        self.client_curve_key_public = key.public_key().export_key(format='PEM')
        

    def SendInitMessage(self, clientId) -> bytes:
        messageData = {
            "type": "INI",
            "pub_key": self.client_key_public,
            "pub_curve_key":  self.client_curve_key_public
        }
        messageToEncode = {
            "client_id": clientId.int,
            "data": messageData
        }

        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")

        session_key = get_random_bytes(16)
        
        encodedSessionKey = self.server_cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        encodedMessage, tag = cipher_aes.encrypt_and_digest(messageToEncodeBytes)
        
        initMessageBytes = self.address.encode("utf-8") + \
                           encodedSessionKey + \
                           cipher_aes.nonce + \
                           tag + \
                           encodedMessage
        

        print('sent init! message length: {} encodedSessionKey length:{}'.format(len(initMessageBytes),len(encodedSessionKey)))
        return initMessageBytes
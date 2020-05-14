import getpass 
import json
import io
import uuid 
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


class ClientLogic:
    def __init__(self, address):
        self.clientId = uuid.uuid1()

        # Generating RSA keys
        client_key = RSA.generate(2048)
        self.client_key_private = client_key.export_key()
        self.client_key_public = client_key.publickey().export_key().decode('utf-8')
        self.client_private_cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.client_key_private))
        
        self.address = address

        # Generating signing key
        curveKey = ECC.generate(curve='P-256')
        self.signer = DSS.new(curveKey, 'fips-186-3')
        self.client_curve_key_private = curveKey.export_key(format='PEM')
        self.client_curve_key_public = curveKey.public_key().export_key(format='PEM')

        self.userName = ''
        self.userPassword = ''

        serverPublicKey = RSA.import_key(open("public_server_rsa_key.pem").read())
        self.server_cipher_rsa = PKCS1_OAEP.new(serverPublicKey)
        self.server_curve_key = ECC.import_key(open('public_server_curve_key.pem').read())


    def GetCredentials(self):
        self.userName = input("Enter your username: ")
        self.userPassword = getpass.getpass()
        return self.userName, self.userPassword


    def GenerateRsaKeys(self):
        client_key = RSA.generate(2048)
        self.client_key_private = client_key.export_key()
        self.client_key_public = client_key.publickey().export_key().decode('utf-8')
        self.client_private_cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.client_key_private))
        

    def SignMessage(self, message) -> bytes:
        hashed_message = SHA256.new(message)
        signature = self.signer.sign(hashed_message)
        return signature

    
    def EncodeMessageWithAes(self, message) -> bytes:
        messageKey = get_random_bytes(16)
        encodedMessageKey = self.server_cipher_rsa.encrypt(messageKey)
        cipher_aes = AES.new(messageKey, AES.MODE_EAX)
        encodedMessage, tag = cipher_aes.encrypt_and_digest(message)
        return self.address.encode("utf-8") + encodedMessageKey + cipher_aes.nonce + tag + encodedMessage

    
    def VerifyServerSignature(self, signature, msg_data_bytes):
        hashedMessage = SHA256.new(msg_data_bytes)
        verifier = DSS.new(self.server_curve_key, 'fips-186-3')

        msg_obj = json.loads(msg_data_bytes.decode("utf-8"))

        try:
            verifier.verify(hashedMessage, signature)
            print("The message is authentic.")
            print(json.dumps(msg_obj, indent=2))
        except ValueError:
            print("The message is not authentic.")


    def ResolveServerMessage(self, networkInterface):
        status, incoming_byte_message = networkInterface.receive_msg(blocking=True)
        f = io.BytesIO(incoming_byte_message)
        encodedMessageKey, nonce, tag, ciphertext = \
            [ f.read(x) for x in (256, 16, 16, -1) ]
        
        messageKey = self.client_private_cipher_rsa.decrypt(encodedMessageKey)

        cipher_aes = AES.new(messageKey, AES.MODE_EAX, nonce)
        byte_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

        f = io.BytesIO(byte_msg)
        signature, msg_data_bytes = [ f.read(x) for x in (64,-1) ]

        self.VerifyServerSignature(signature, msg_data_bytes)


    def CreateMessage(self, messageData):
        messageToEncode = {
            "client_id": self.clientId.int,
            "data": messageData 
        }
        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")
        messageWithSign = self.SignMessage(messageToEncodeBytes) + messageToEncodeBytes

        return self.EncodeMessageWithAes(messageWithSign)


    def SendInitMessage(self) -> bytes:
        messageData = {
            "type": "INI",
            "pub_key": self.client_key_public,
            "pub_curve_key":  self.client_curve_key_public
        }
        messageToEncode = {
            "client_id": self.clientId.int,
            "data": messageData
        }

        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")
        messageWithSign = get_random_bytes(64) + messageToEncodeBytes

        messageBytes = self.EncodeMessageWithAes(messageWithSign)

        print('sent init.')
        return messageBytes


    def SendLogInMessage(self):
        messageData = {
            "type": "LIN",
            "username": self.userName,
            "password": self.userPassword
        }

        messageBytes = self.CreateMessage(messageData)

        print('sent login.')
        return messageBytes


    def SendRegistrationMessage(self):
        messageData = {
            "type": "REG",
            "username": self.userName,
            "password": self.userPassword
        }

        messageBytes = self.CreateMessage(messageData)
        
        print('sent registration.')
        return messageBytes


    def SendExitMessage(self):
        messageData = {
            "type": "EXT"
        }
        return self.CreateMessage(messageData)
    

    def SendCreateDirectoryMessage(self):
        messageData = {
            "type": "MKD"
        }
        return self.CreateMessage(messageData)

    
    def SendRemoveDirectoryMessage(self):
        messageData = {
            "type": "RMD"
        }
        return self.CreateMessage(messageData)


    def SendChangeDirectoryMessage(self):
        messageData = {
            "type": "CWD"
        }
        return self.CreateMessage(messageData)

    
    def SendUploadFileMessage(self):
        messageData = {
            "type": "UPL"
        }
        return self.CreateMessage(messageData)
        
    
    def SendDownloadFileMessage(self):
        messageData = {
            "type": "DNL"
        }
        return self.CreateMessage(messageData)
        
    
    def SendListFilesMessage(self):
        messageData = {
            "type": "LST"
        }
        return self.CreateMessage(messageData)
           
    
    def SendRemoveFileMessage(self):
        messageData = {
            "type": "RMF"
        }
        return self.CreateMessage(messageData)

    
    def SendGetWorkingDirectoryMessage(self):
        messageData = {
            "type": "GWD"
        }
        return self.CreateMessage(messageData)
    





        


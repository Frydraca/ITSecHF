import getpass 
import json
import io
import uuid 
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from datetime import datetime


class ClientLogic:
    def __init__(self, address):
        self.clientId = uuid.uuid1()
        self.address = address
        self.userName = ''
        self.userPassword = ''
        self.SequenceId = 0

        # Generating RSA keys
        client_key = RSA.generate(2048)
        self.client_key_private = client_key.export_key()
        self.client_key_public = client_key.publickey().export_key().decode('utf-8')
        self.client_private_cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.client_key_private))

        # Generating signing key
        curveKey = ECC.generate(curve='P-256')
        self.signer = DSS.new(curveKey, 'fips-186-3')
        self.client_curve_key_private = curveKey.export_key(format='PEM')
        self.client_curve_key_public = curveKey.public_key().export_key(format='PEM')

        # Load server public keys
        serverPublicKey = RSA.import_key(open("public_server_rsa_key.pem").read())
        self.server_cipher_rsa = PKCS1_OAEP.new(serverPublicKey)
        self.server_curve_key = ECC.import_key(open('public_server_curve_key.pem').read())


    def GetCredentials(self):
        self.userName = input("Enter your username: ")
        self.userPassword = getpass.getpass()
        return self.userName, self.userPassword


    def create_timestamp(self):
        now = datetime.now()
        return datetime.timestamp(now)

    
    def addSequenceId(self):
        self.SequenceId += 1
        return self.SequenceId

    
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

        validity = False
        try:
            verifier.verify(hashedMessage, signature)

            validity = True

        except ValueError:
            print("The message's signature is not valid.")
            validity = False

        return validity, msg_obj


    def VerifyServerSequenceId(self, messageServerSequenceId):
        if messageServerSequenceId == self.SequenceId:
            return True
        else: 
            print("The sequence id is invalid")
            return False

    
    def VerifyServerTimestamp(self, messageServerTimestamp):
        currentTime = datetime.now()
        serverTime = datetime.fromtimestamp(messageServerTimestamp)
        if currentTime > serverTime:
            deltaTime = currentTime - serverTime
            if deltaTime.total_seconds() < 60:
                return True
            else:
                print('The server timestamp is invalid')
                return False
        else:
            print('The server timestamp is invalid')
            return False


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



        validity, messageObject = self.VerifyServerSignature(signature, msg_data_bytes)
        if "type" in messageObject:
            self.SequenceId += 1
            messageServerSequenceId = messageObject["seq_id"]
            sequenceValidity = self.VerifyServerSequenceId(messageServerSequenceId)
            messageServerTimestamp = messageObject["timestamp"]
            timestampValidity = self.VerifyServerTimestamp(messageServerTimestamp)
        else:
            sequenceValidity = True
            timestampValidity = True
    

        if validity and sequenceValidity and timestampValidity:
            print("The message is authentic.")
        else:
            print("The message is not authentic.")
        print(json.dumps(messageObject, indent=2))


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
            "password": self.userPassword,
            "timestamp": self.create_timestamp()
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
            "type": "EXT",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
    

    def SendCreateDirectoryMessage(self, directoryName):
        messageData = {
            "type": "MKD",
            "dir_name": directoryName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendRemoveDirectoryMessage(self, directoryName):
        messageData = {
            "type": "RMD",
            "dir_name": directoryName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)


    def SendChangeDirectoryMessage(self, path):
        messageData = {
            "type": "CWD",
            "path": path,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendUploadFileMessage(self):
        messageData = {
            "type": "UPL",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
        
    
    def SendDownloadFileMessage(self):
        messageData = {
            "type": "DNL",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
        
    
    def SendListFilesMessage(self):
        messageData = { 
            "type": "LST",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
            }
        return self.CreateMessage(messageData)
           
    
    def SendRemoveFileMessage(self, fileName):
        messageData = {
            "type": "RMF",
            "file_name": fileName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendGetWorkingDirectoryMessage(self):
        messageData = {
            "type": "GWD",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
    





        


import getpass 
import json
import io
import uuid 
import sys
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode
from datetime import datetime


class ClientLogic:
    def __init__(self, address):
        self.clientId = uuid.uuid1()
        self.address = address
        self.userName = ''
        self.userPassword = ''
        self.sequenceId = 0
        self.currentDirectory =''

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
        self.sequenceId += 1
        return self.sequenceId

    
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

        try:
            verifier.verify(hashedMessage, signature)

            return True

        except ValueError:
            print("The message's signature is not valid.")
            return False


    def VerifyServerSequenceId(self, messageServerSequenceId):
        if messageServerSequenceId == self.sequenceId:
            return True
        else: 
            print("The sequence id is invalid")
            return False

    
    def VerifyServerTimestamp(self, messageServerTimestamp):
        currentTime = datetime.now()
        serverTime = datetime.fromtimestamp(messageServerTimestamp)
        if currentTime > serverTime:
            deltaTime = currentTime - serverTime
            if deltaTime.total_seconds() < 5:
                return True
            else:
                print('The server timestamp is invalid')
                return False
        else:
            print('The server timestamp is invalid')
            return False

    
    def VerifyMessage(self, signature, msg_data_bytes):

        messageObject = json.loads(msg_data_bytes.decode("utf-8"))

        signatureValidity = self.VerifyServerSignature(signature, msg_data_bytes)

        self.sequenceId += 1
        messageServerSequenceId = messageObject["seq_id"]
        sequenceValidity = self.VerifyServerSequenceId(messageServerSequenceId)
        messageServerTimestamp = messageObject["timestamp"]
        timestampValidity = self.VerifyServerTimestamp(messageServerTimestamp)    

        if signatureValidity and sequenceValidity and timestampValidity:
            print("The message is authentic.")
            return True
        else:
            print("The message is not authentic.")
            return False
    

    def DecodeMessage(self, networkInterface):
        status, incoming_byte_message = networkInterface.receive_msg(blocking=True)
        f = io.BytesIO(incoming_byte_message)
        encodedMessageKey, nonce, tag, ciphertext = \
            [ f.read(x) for x in (256, 16, 16, -1) ]
        
        messageKey = self.client_private_cipher_rsa.decrypt(encodedMessageKey)

        cipher_aes = AES.new(messageKey, AES.MODE_EAX, nonce)
        byte_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)
        f.close()

        f = io.BytesIO(byte_msg)
        signature, msg_data_bytes = [ f.read(x) for x in (64,-1) ]
        f.close()
        return signature, msg_data_bytes


    def ResolveServerMessage(self, networkInterface):
        signature, msg_data_bytes = self.DecodeMessage(networkInterface)
        messageObject = json.loads(msg_data_bytes.decode("utf-8"))

        print(json.dumps(messageObject, indent=2))

        validity = self.VerifyMessage(signature, msg_data_bytes)    

        if not validity:
            return False

        if 'type' in messageObject:
            if messageObject['type'] == 'MKD':
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'RMD':
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'CWD':
                if type(messageObject['response']) == str:
                    self.currentDirectory = messageObject['response']
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'UPL':
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'DNL':
                if type(messageObject['response']) == str:
                    print("TODO DNL response")
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'LST':
                if type(messageObject['response']) == list:
                    for element in messageObject['response']:
                        print(element)
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'GWD':
                if type(messageObject['response']) == str:
                    self.currentDirectory = messageObject['response']
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'RMF':
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'SVU':
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                else:
                    error = messageObject['response']['error']
                    print(error)
                    return False
            elif messageObject['type'] == 'EXT':
                print(messageObject['response'])
        
        return True
        

    def ResolveInitServerMessage(self, networkInterface):
        signature, msg_data_bytes = self.DecodeMessage(networkInterface)

        signatureValidity = self.VerifyServerSignature(signature, msg_data_bytes)

        if signatureValidity:
            messageObject = json.loads(msg_data_bytes.decode("utf-8"))
            if type(messageObject['response']) == str:
                print(messageObject['response'])
            else:
                error = messageObject['response']['error']
                print(error)
                sys.exit()
        else:
            print("Couldn't create connection with server, exiting from client.")
            sys.exit()

    
    def ResolveLoginServerMessage(self, networkInterface):
        signature, msg_data_bytes = self.DecodeMessage(networkInterface)

        signatureValidity = self.VerifyServerSignature(signature, msg_data_bytes)

        
        if signatureValidity:
            messageObject = json.loads(msg_data_bytes.decode("utf-8"))
            messageServerTimestamp = messageObject["timestamp"]
            timestampValidity = self.VerifyServerTimestamp(messageServerTimestamp)
            if timestampValidity:
                if type(messageObject['response']) == str:
                    print(messageObject['response'])
                    return True
                else:
                    error = messageObject['response']['error']
                    print(error)
        
        print("Login was not successful, exiting client")
        sys.exit()

    
    def ResolveRegServerMessage(self, networkInterface):
        signature, msg_data_bytes = self.DecodeMessage(networkInterface)

        signatureValidity = self.VerifyServerSignature(signature, msg_data_bytes)
        
        if signatureValidity:
            messageObject = json.loads(msg_data_bytes.decode("utf-8"))
            if type(messageObject['response']) == str:
                print(messageObject['response'])
            else:
                error = messageObject['response']['error']
                print(error)
        else:
            print("Registration was not successful, exiting client")


    def ResolveDownloadFileServerMessage(self, networkInterface, contentSize):
        status, incoming_byte_message = networkInterface.receive_msg(blocking=True)
        f = io.BytesIO(incoming_byte_message)
        encodedMessageKey, nonce, tag, ciphertext = \
            [ f.read(x) for x in (256, 16, 16, -1) ]
        
        messageKey = self.client_private_cipher_rsa.decrypt(encodedMessageKey)

        cipher_aes = AES.new(messageKey, AES.MODE_EAX, nonce)
        byte_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)
        f.close()

        f = io.BytesIO(byte_msg)
        signature, fileContent, msg_data_bytes = [ f.read(x) for x in (64, contentSize, -1) ]
        f.close()

        messageObject = json.loads(msg_data_bytes.decode("utf-8"))

        print(json.dumps(messageObject, indent=2))

        validity = self.VerifyMessage(signature, fileContent + msg_data_bytes)    

        if not validity:
            return False

        if type(messageObject['response']) == str:
            return True, self.DecryptFile(fileContent)
        else:
            error = messageObject['response']['error']
            print(error)
            return False, ''


    
    def ResolveDNLServerMessage(self, networkInterface):
        signature, msg_data_bytes = self.DecodeMessage(networkInterface)
        messageObject = json.loads(msg_data_bytes.decode("utf-8"))

        print(json.dumps(messageObject, indent=2))

        validity = self.VerifyMessage(signature, msg_data_bytes)    

        if not validity:
            return False

        if messageObject['type'] == 'DNL':
            if type(messageObject['response']) == str:
                return True, int(messageObject['response'])
            else:
                error = messageObject['response']['error']
                print(error)
                return False, 0

    
    def CreateMessage(self, messageData):
        messageToEncode = {
            "client_id": self.clientId.int,
            "data": messageData 
        }
        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")
        messageWithSign = self.SignMessage(messageToEncodeBytes) + messageToEncodeBytes

        return self.EncodeMessageWithAes(messageWithSign)


    def SendINI(self) -> bytes:
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


    def SendLIN(self):
        messageData = {
            "type": "LIN",
            "username": self.userName,
            "password": self.userPassword,
            "timestamp": self.create_timestamp()
        }

        messageBytes = self.CreateMessage(messageData)

        print('sent login.')
        return messageBytes


    def SendREG(self):
        messageData = {
            "type": "REG",
            "username": self.userName,
            "password": self.userPassword
        }

        messageBytes = self.CreateMessage(messageData)
        
        print('sent registration.')
        return messageBytes


    def SendEXT(self):
        messageData = { 
            "type": "EXT",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
    

    def SendMKD(self, directoryName):
        messageData = {
            "type": "MKD",
            "dir_name": directoryName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendRMD(self, directoryName):
        messageData = {
            "type": "RMD",
            "dir_name": directoryName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)


    def SendCWD(self, path):
        messageData = {
            "type": "CWD",
            "path": path,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendUPL(self, filename, filesize):
        messageData = {
            "type": "UPL",
            "filename": filename,
            "upload_size": filesize,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
        
    
    def SendDNL(self, filename):
        messageData = {
            "type": "DNL",
            "filename": filename,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)
        
    
    def SendLST(self):
        messageData = { 
            "type": "LST",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
            }
        return self.CreateMessage(messageData)
           
    
    def SendRMF(self, fileName):
        messageData = {
            "type": "RMF",
            "filename": fileName,
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)

    
    def SendGWD(self):
        messageData = {
            "type": "GWD",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }
        return self.CreateMessage(messageData)


    def UploadFileMessage(self, content):
        messageData = {
            "type": "SVU",
            "timestamp": self.create_timestamp(),
            "seq_id": self.addSequenceId()
        }

        messageToEncode = {
            "client_id": self.clientId.int,
            "data": messageData 
        }
        messageToEncodeBytes = json.dumps(messageToEncode).encode("utf-8")
        messageWithSign = self.SignMessage(content + messageToEncodeBytes) + \
                          content + messageToEncodeBytes

        return self.EncodeMessageWithAes(messageWithSign)

    
    def EncryptFile(self, filepath):

        salt = get_random_bytes(16)
        cbc_key = PBKDF2(self.userPassword, salt, 16, count=100000, hmac_hash_module=SHA512)

        with open(filepath, 'rb') as file:

            fileData = file.read()
            cipher = AES.new(cbc_key, AES.MODE_CBC)
            ciphertext_bytes = cipher.encrypt(pad(fileData, AES.block_size))
            iv = cipher.iv
            content = salt + iv + ciphertext_bytes
            return content, len(content)


    def DecryptFile(self, content):

        salt, iv, ciphertext = \
            [ content.read(x) for x in (16, 16, -1) ]

        cbc_key = PBKDF2(self.userPassword, salt, 16, count=100000, hmac_hash_module=SHA512)

        cipher = AES.new(cbc_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        return plaintext


    





        


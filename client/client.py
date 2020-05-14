import sys
import json
import getopt
import io
sys.path += ['..']

from netsim.netinterface import network_interface
from client_logic import ClientLogic
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

import uuid 
      

try:
    opts, args = getopt.getopt(sys.argv[1:], 'r:', ['registrate'])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    sys.exit(1)


clientAddress = "C"
clientLogic = ClientLogic(clientAddress)
netif = network_interface("../netsim/", clientAddress)

for opt, arg in opts:
    if opt in ('-r', '--registrate'):
        print('Registration')
        userNameReg, userPasswordReg = clientLogic.GetCredentials()
        sys.exit()

print('Login')
userNameLog, userPasswordLog = clientLogic.GetCredentials()

clientId = uuid.uuid1() 
clientLogic.GenerateRsaKeys()
clientLogic.GenerateSignKey()
netif.send_msg("A", clientLogic.SendInitMessage(clientId))

############################# Test answer catch #############################
status, incoming_byte_message = netif.receive_msg(blocking=True)
f = io.BytesIO(incoming_byte_message)
enc_session_key, nonce, tag, ciphertext = \
    [ f.read(x) for x in (RSA.import_key(clientLogic.client_key_private).size_in_bytes(), 16, 16, -1) ]

cipher_rsa = PKCS1_OAEP.new(RSA.import_key(clientLogic.client_key_private))
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
byte_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

f = io.BytesIO(byte_msg)
signature, msg_data_bytes = \
    [ f.read(x) for x in (64,-1) ]

server_curve_key = ECC.import_key(open('public_server_curve_key.pem').read())
h = SHA256.new(msg_data_bytes)
verifier = DSS.new(server_curve_key, 'fips-186-3')

msg_obj = json.loads(msg_data_bytes.decode("utf-8"))

try:
    verifier.verify(h, signature)
    print("The message is authentic.")
    print(json.dumps(msg_obj, indent=2))
except ValueError:
    print("The message is not authentic.")
############################# Test answer catch #############################

while True:
    userInput = input(">> ").split()
    if len(userInput) == 0:
        print("Error: No input was given.")
        continue

    if userInput[0] == 'exit':
        print('Logging out')
        break
    elif userInput[0] == 'mkdir':
        if len(userInput) < 2:
            print('Error: Directory name was not provided')
        else:
            print('Creating a new directory: ' + userInput[1])
    elif userInput[0] == 'rmd':
        if len(userInput) < 2:
            print('Error: Directory name was not provided')
        else:
            print('Deleting directory: ' + userInput[1])
    elif userInput[0] == 'cd':
        if len(userInput) < 2:
            print('Error: Path was not provided')
        else:
            print('Changing directory to: ' + userInput[1])
    elif userInput[0] == 'ls':
        print("Listing contents in the directory")
    elif userInput[0] == 'upl':
        if len(userInput) < 2:
            print('Error: Path was not provided')
        else:
            print("Uploading file: " + userInput[1])
    elif userInput [0] == 'dnl':
        if len(userInput) < 3:
            print('Error: File name or path was not provided')
        else:
            print('Downloading file: ' + userInput[1] 
            + " to directory: " + userInput[2])
    elif userInput[0] == 'rmf':
        if len(userInput) < 2:
            print('Error: File name was not provided')
        else:
            print('Deleting file: ' + userInput[1])  
    else:
        print("Invalid command")
    

# sent=netif.send_msg("A", b"alma")
# print(sent)
# status, message = netif.receive_msg(blocking=True)

# print(message)


import getpass 
import sys
import getopt
import json
sys.path += ['..']

from netsim.netinterface import network_interface
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import uuid 
  

client_key_public = ''
client_key_private = ''


def GetCredentials():
    userName = input("Enter your username: ")
    userPassword = getpass.getpass()
    return userName, userPassword


def GenerateRsaKeys():
    client_key = RSA.generate(2048)
    client_key_private = client_key.export_key()
    client_key_public = client_key.publickey().export_key()



def GenerateSignKey():
    key = ECC.generate(curve='P-256')
    f = open('client_sign_key.pem','wt')
    f.write(key.export_key(format='PEM'))
    f.close()

def SendInitMessage():
    curve_pub_key = ECC.generate(curve='P-256').export_key(format='PEM')

    messageData = {
        "type": "INI",
        "pub_key": client_key_public,
        "pub_curve_key":  curve_pub_key
    }
    messageToEncode = {
        "client_id": clientId.int,
        "data": messageData
    }

    messageToEncodeString = json.dumps(messageToEncode).encode("utf-8")

    serverPublicKey = RSA.import_key(open("public_server_rsa_key.pem").read())
    session_key = get_random_bytes(16)
    
    cipher_rsa = PKCS1_OAEP.new(serverPublicKey)
    encodedSessionKey = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    encodedMessage, tag = cipher_aes.encrypt_and_digest(messageToEncodeString)

    initMessage = {
        "enc_session_key": int.from_bytes(encodedSessionKey, 'big'),
        "tag": int.from_bytes(tag, 'big'),
        "nonce": int.from_bytes(cipher_aes.nonce, 'big'),
        "ciphertext": int.from_bytes(encodedMessage, 'big')
    }

    initMessageString = json.dumps(initMessage).encode("utf-8")

    netif.send_msg("A", initMessageString)
    print('sent init')
    

try:
    opts, args = getopt.getopt(sys.argv[1:], 'r:', ['registrate'])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    sys.exit(1)

for opt, arg in opts:
    if opt in ('-r', '--registrate'):
        print('Registration')
        userNameReg, userPasswordReg = GetCredentials()
        sys.exit()

clientId = uuid.uuid1() 

clientAddress = "C"

netif = network_interface("../netsim/", clientAddress)

print('Login')
userNameLog, userPasswordLog = GetCredentials()

GenerateRsaKeys()
GenerateSignKey()

SendInitMessage()

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

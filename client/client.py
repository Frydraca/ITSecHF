import sys
import json
import getopt

sys.path += ['..']

from netsim.netinterface import network_interface
from client_logic import ClientLogic
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS      

try:
    opts, args = getopt.getopt(sys.argv[1:], 'r:', ['registrate'])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    sys.exit(1)



clientAddress = "C"
clientLogic = ClientLogic(clientAddress)
netif = network_interface("../netsim/", clientAddress)

netif.send_msg("A", clientLogic.SendInitMessage())


clientLogic.ResolveServerMessage(netif)

for opt, arg in opts:
    if opt in ('-r', '--registrate'):
        print('Registration')
        clientLogic.GetCredentials()
        netif.send_msg("A", clientLogic.SendRegistrationMessage())
        clientLogic.ResolveServerMessage(netif)
        sys.exit()

print('Login')
userNameLog, userPasswordLog = clientLogic.GetCredentials()
netif.send_msg("A", clientLogic.SendLogInMessage())
clientLogic.ResolveServerMessage(netif)

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

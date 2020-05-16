import sys
import json
import getopt
import os

sys.path += ['..']

from netsim.netinterface import network_interface
from client_logic import ClientLogic
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS  

def ExitInput(netif, clientLogic):
    print('Logging out')
    netif.send_msg("A", clientLogic.SendEXT())
    clientLogic.ResolveServerMessage(netif)


def CreateDirectoryInput(netif, clientLogic, userInput):
    if len(userInput) < 2:
        print('Error: Directory name was not provided')
    else:
        print('Creating a new directory: ' + userInput[1])
        netif.send_msg("A", clientLogic.SendMKD(userInput[1]))
        clientLogic.ResolveServerMessage(netif)


def RemoveDirectoryInput(netif, clientLogic, userInput):
    if len(userInput) < 2:
        print('Error: Directory name was not provided')
    else:
        print('Deleting directory: ' + userInput[1])
        netif.send_msg("A", clientLogic.SendRMD(userInput[1]))
        clientLogic.ResolveServerMessage(netif)


def ChangingDirectoryInput(netif, clientLogic, userInput):
    if len(userInput) < 2:
        print('Error: Path was not provided')
    else:
        print('Changing directory to: ' + userInput[1])
        netif.send_msg("A", clientLogic.SendCWD(userInput[1]))
        clientLogic.ResolveServerMessage(netif)


def ListDirectoryInput(netif, clientLogic):
    print("Listing contents in the directory")
    netif.send_msg("A", clientLogic.SendLST())
    clientLogic.ResolveServerMessage(netif)


def UploadFileInput(netif, clientLogic, userInput):
    if len(userInput) < 2:
        print('Error: Path was not provided')
    else:
        if os.path.isfile(userInput[1]):
            print("Uploading file: " + userInput[1])
            content, content_size = clientLogic.EncryptFile(userInput[1])
            netif.send_msg("A", \
                clientLogic.SendUPL(os.path.basename(userInput[1]), content_size))
            if clientLogic.ResolveServerMessage(netif):
                netif.send_msg("A", clientLogic.UploadFileMessage(content))
                clientLogic.ResolveServerMessage(netif)
        else:
            print('Error: file does not exists')


def DownloadFileInput(netif, clientLogic, userInput):
    if len(userInput) < 3:
        print('Error: File name or path was not provided')
    else:
        if os.path.isdir(userInput[2]):
            print('Downloading file: ' + userInput[1] 
            + " to directory: " + userInput[2])
            netif.send_msg("A", clientLogic.SendDNL(userInput[1]))
            status, contentSize = clientLogic.ResolveDNLServerMessage(netif)
            if status:
                success, plaintext = clientLogic.ResolveDownloadFileServerMessage(netif, contentSize)
                if success:
                    file_out = open(os.path.normpath(userInput[2] + "/" + \
                         os.path.basename(userInput[1])), "w")
                    [ file_out.write(x) for x in (plaintext.decode('utf-8')) ]
                    file_out.close()
        else:
            print('Error: download target directory does not exists')


def RemoveFileInput(netif, clientLogic, userInput):
    if len(userInput) < 2:
        print('Error: File name was not provided')
    else:
        print('Deleting file: ' + userInput[1])
        netif.send_msg("A", clientLogic.SendRMF(userInput[1]))
        clientLogic.ResolveServerMessage(netif)


try:
    opts, args = getopt.getopt(sys.argv[1:], 'r:', ['registrate'])
except getopt.GetoptError:
    print('Error: Unknown option detected.')
    sys.exit(1)



clientAddress = "C"
clientLogic = ClientLogic(clientAddress)
netif = network_interface("../netsim/", clientAddress)

netif.send_msg("A", clientLogic.SendINI())
clientLogic.ResolveInitServerMessage(netif)

for opt, arg in opts:
    if opt in ('-r', '--registrate'):
        print('Registration')
        clientLogic.GetCredentials()
        netif.send_msg("A", clientLogic.SendREG())
        clientLogic.ResolveRegServerMessage(netif)
        sys.exit()

print('Login')
userNameLog, userPasswordLog = clientLogic.GetCredentials()
netif.send_msg("A", clientLogic.SendLIN())
clientLogic.ResolveLoginServerMessage(netif)
netif.send_msg("A", clientLogic.SendGWD())
clientLogic.ResolveServerMessage(netif)

# clientLogic.EncryptFile('test.txt')
# clientLogic.DecryptFile('temp.bin')

while True:
    print()
    userInput = input(clientLogic.userName + \
        ": " + clientLogic.currentDirectory + " >> ").split()
    if len(userInput) == 0:
        print("Error: No input was given.")
        continue

    if userInput[0] == 'mkdir':
        CreateDirectoryInput(netif, clientLogic, userInput)
    elif userInput[0] == 'rmd':
        RemoveDirectoryInput(netif, clientLogic, userInput)
    elif userInput[0] == 'cd':
        ChangingDirectoryInput(netif, clientLogic, userInput)
    elif userInput[0] == 'upl':
        UploadFileInput(netif, clientLogic, userInput)
    elif userInput[0] == 'dnl':
        DownloadFileInput(netif, clientLogic, userInput)
    elif userInput[0] == 'ls':
        ListDirectoryInput(netif, clientLogic)
    elif userInput[0] == 'rmf':
        RemoveFileInput(netif, clientLogic, userInput)
    elif userInput[0] == 'exit':
        ExitInput(netif, clientLogic)
        break
    else:
        print("Invalid command")
    

# sent=netif.send_msg("A", b"alma")
# print(sent)
# status, message = netif.receive_msg(blocking=True)

# print(message)

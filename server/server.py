import sys
sys.path += ['..']

from netsim.netinterface import network_interface
from getpass import getpass
from Crypto.PublicKey import RSA
from business_logic import BLL

netif = network_interface("../netsim/", 'A')
password = getpass()
private_key = RSA.import_key(open("enceypted_server_rsa_key.bin").read(), passphrase=password)
bll = BLL()

print("Server is running press CTRL+C to stop it!")
while True:	
    status, msg = netif.receive_msg(blocking=False)
    if status:
        bll.resolve_message(msg)

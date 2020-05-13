import sys
sys.path += ['..']

from netsim.netinterface import network_interface
from getpass import getpass
from Crypto.PublicKey import RSA,ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from business_logic import BLL

address = 'A'
netif = network_interface("../netsim/", address)
password = getpass()
private_key = RSA.import_key(open("enceypted_server_rsa_key.bin").read(), passphrase=password)
cipher_rsa = PKCS1_OAEP.new(private_key)
curve_key = ECC.import_key(open('encrypted_server_curve_key.bin').read(), passphrase=password)
signer = DSS.new(curve_key, 'fips-186-3')
bll = BLL()

print()
print("Lisstening on {}".format(address))
print("Server is running press CTRL+C to stop it!")
while True:	
    status, enc_msg = netif.receive_msg(blocking=False)
    if status:
        byte_msg = cipher_rsa.decrypt(enc_msg)
        bll.resolve_message(byte_msg)
        #NOT DONE
        h = SHA256.new("message")
        signature = signer.sign(h)

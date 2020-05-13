import sys
import json 
sys.path += ['..']

from netsim.netinterface import network_interface
from getpass import getpass
from Crypto.PublicKey import RSA,ECC
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Signature import DSS
from business_logic import BLL

address = 'A'
netif = network_interface("../netsim/", address)
password = getpass()
private_key = RSA.import_key(open("enceypted_server_rsa_key.bin").read(), passphrase=password)
cipher_rsa = PKCS1_OAEP.new(private_key)
curve_key = ECC.import_key(open('encrypted_server_curve_key.bin').read(), passphrase=password)
signer = DSS.new(curve_key, 'fips-186-3')
bll = BLL(signer)

print()
print("Lisstening on {}".format(address))
print("Server is running press CTRL+C to stop it!")
while True:	
    status, incoming_byte_message = netif.receive_msg(blocking=False)
    if status:
        incoming_message = incoming_byte_message.decode('utf-8')
        incoming_obj = json.loads(incoming_message)

        session_key = cipher_rsa.decrypt(bll.int_to_bytes(incoming_obj["enc_session_key"]))

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, bll.int_to_bytes(incoming_obj["nonce"]))
        byte_msg = cipher_aes.decrypt_and_verify(bll.int_to_bytes(incoming_obj["ciphertext"]), bll.int_to_bytes(incoming_obj["tag"]))

        result = bll.resolve_message(byte_msg)

        netif.send_msg(incoming_obj["sender"],result)


        
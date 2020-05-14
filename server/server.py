import sys
import json 
import io
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
private_key = RSA.import_key(open("encrypted_server_rsa_key.bin").read(), \
                passphrase=password)
modulus_len = private_key.size_in_bytes()
cipher_rsa = PKCS1_OAEP.new(private_key)
curve_key = ECC.import_key(open('encrypted_server_curve_key.bin').read(), \
                passphrase=password)
signer = DSS.new(curve_key, 'fips-186-3')
bll = BLL(signer)

print()
print("Listening on {}".format(address))
print("Server is running press CTRL+C to stop it!")
while True:	
    status, incoming_byte_message = netif.receive_msg(blocking=False)
    if status:        
        f = io.BytesIO(incoming_byte_message)
        sender, enc_session_key, nonce, tag, ciphertext = \
            [ f.read(x) for x in (1 ,modulus_len, 16, 16, -1) ]

        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        byte_msg = cipher_aes.decrypt_and_verify(ciphertext, tag)

        result = bll.resolve_message(byte_msg)

        netif.send_msg(sender.decode("utf-8"),result)


        
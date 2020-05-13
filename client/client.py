
import sys
sys.path += ['..']

from netsim.netinterface import network_interface

netif = network_interface("../netsim/", "C")

sent=netif.send_msg("A", b"alma")
print(sent)
status, message = netif.receive_msg(blocking=True)

print(message)

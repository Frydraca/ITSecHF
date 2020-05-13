import sys
sys.path += ['..']

from netsim.netinterface import network_interface

netif = network_interface("../netsim", 'A')		
status, msg = netif.receive_msg(blocking=True)		
print(msg)
netif.send_msg('C', 'At jott')

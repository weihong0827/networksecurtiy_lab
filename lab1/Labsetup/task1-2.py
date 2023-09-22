from scapy.all import *

a = IP(dst='10.9.0.5')
b = ICMP()
p = a/b
send(p)

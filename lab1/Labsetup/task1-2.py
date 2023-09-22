from scapy.all import *

a = IP(src='233.233.233.233',dst='10.9.0.5')
b = ICMP()
p = a/b
send(p)

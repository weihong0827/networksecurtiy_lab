from scapy.all import *

filterICMP = 'icmp'
filterTCP = 'src host 10.9.0.5 and dst port 12345'
filterSubnet  = ' src net x.x.x.x/16'

def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-1714b192a2df', filter=filterTCP,prn=print_pkt)





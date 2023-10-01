---
tags:
  - "#lesson"
  - lab
week: 2
creation date: 2023-09-22 11:45
modification date: Friday 22nd September 2023 11:45:40
reviewed: 
summary: 
course_name: Network Security
URL: https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/
publish: true
---
# Task 1.1A Sniffing packets
## The code

```python
from scapy.all import *

def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-1714b192a2df', filter='icmp',prn=print_pkt)
```
## Executing
You will need 3 terminals to test this functionality
### Terminal 1 
Switch to the `seed` user and navigate to the current lab directory
run `dcup`
This command is short for `docker-compose up` which build the necessary docker containers for this lab
More explanation of the setup can be found in the lab instructions

### Terminal 2
Run `ifconfig` and watch out for the one that starts with `br-` that is the network that the docker containers are running in
```
br-1714b192a2df: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 10.9.0.1  netmask 255.255.255.0  broadcast 10.9.0.255
        ether 02:42:89:d5:83:ca  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`sudo python3 task1.py`
it will start sniffing packets in `br-1714b192a2df` which is taken from `ifconfig`

## Terminal 3
Run `ping 10.9.0.5` to send a `ICMP request` to one of your docker containers in the network
This `ICMP` request will then be sniffed by our code that is running in terminal 2

## Result
![](attachments/Pasted%20image%2020230922143656.png)
We can see that there are two `ICMP` network packets sniffed
The first request is is a `echo-request` with `src 10.9.0.1` and `dst 10.9.0.5`. This request is what we sent from terminal 3 to the docker container at `10.9.0.5`
The second request is is a `echo-reply` with `src 10.9.0.5` and `dst 10.9.0.1`. This is a reply that is sent from the docker container at `10.9.0.5` back to the sender
## Running without root privileges
Running `python3 task1.py` will result in a error 
```
Traceback (most recent call last):
  File "task1-1.py", line 9, in <module>
    pkt = sniff(iface='br-1714b192a2df', filter=filterICMP,prn=print_pkt)
  File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 1311, in sniff
    sniffer._run(*args, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/scapy/sendrecv.py", line 1171, in _run
    sniff_sockets[_RL2(iface)(type=ETH_P_ALL, iface=iface,
  File "/usr/local/lib/python3.8/dist-packages/scapy/arch/linux.py", line 484, in __init__
    self.ins = socket.socket(
  File "/usr/lib/python3.8/socket.py", line 231, in __init__
    _socket.socket.__init__(self, family, type, proto, fileno)
PermissionError: [Errno 1] Operation not permitted
```
In order for use sniff, the program needs access to the network interface in `promiscuous mode`. This mode allows the interface to `capture all packets` it sees, not just those destined for it. Enabling promiscuous mode typically `requires elevated privileges`.


# Task 1.1B packet filter

```python
from scapy.all import *

filterICMP = 'icmp'
filterTCP = 'src host 10.9.0.5 and dst port 12345'
filterSubnet  = 'dst net 128.230.0.0/16'

def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-1714b192a2df', filter=filterTCP,prn=print_pkt)
```
By constructing different filter, we can test each of them out individually

## ICMP
Tested previously see [here](#task-11a-sniffing-packets)

## TCP
We will be looking out for a TCP packet that is sent from `10.9.0.5` and to a port `12345`

We will have one terminal running the `task1.py` to sniff the packet
### Sending TCP packet
Run `dockerps` to find out all the docker containers
you will get something like 
```
8dd38b71f942  hostA-10.9.0.5
723eef707c45  hostB-10.9.0.6
1a610bd2a6a3  seed-attacker
```
The string in the first column represents the `container's id` , since we want to send a `tcp` request from the docker container that have the network address of  `10.9.0.5` which has `8dd38b71f942` as its container id
we then run `docksh 8dd38b71f942` to access the terminal in that docker container
In the terminal we run `echo "Test Packet" | nc -n -w1 10.9.0.6 12345 -p 1234 `
This command send a tcp packet with the message `Test Packet` to `10.9.0.6` and destination port number of `12345`
### Result
![](attachments/Pasted%20image%2020230922130113.png)
We can see that the packet being sniffed is a `tcp` packet with `src=10.9.0.5` and `dst=10.9.0.6`, in our code we also specify that the destination port should be `12345` and it is indeed `12345` from the output's `dport` field

## Subnet
```python
from scapy.all import *
filterSubnet  = 'src net 128.230.0.0/16'
def print_pkt(pkt):
    pkt.show()
pkt = sniff(filter=filterSubnet,prn=print_pkt)
```
From the code we have, `filterSubnet = 'dst net 128.230.0.0/16'` means that we are interested in all the packets that is `coming` from `128.230.0.0/16` which means that the first `16 bits` are fixed, hence, any packets from `128.230.0.0` to `128.230.255.255` will be sniffed
We remove the `iface` configuration because the subnet that we are using is not in the docker network.
Now try `ping 128.230.0.1` you will get the following
![](attachments/Pasted%20image%2020230922154210.png)
We received a `echo-reply` packet from `128.230.0.1` and there is no `echo-request` packet because we only want the packets coming from the subnet `128.230.0.0/16`

# Task 1.2 Spoofing attack
```python
from scapy.all import *

a = IP(src= '10.9.0.100' dst='10.9.0.5')
b = ICMP()
p = a/b
send(p)
```
We are spoofing a `ICMP` request from `10.9.0.100` to `10.9.0.5` using the `ICMP` filter from [task 1.1](#task-11a-sniffing-packets) we can see that the packet sniffed is what we intended to send out
by changing the `src` in the script, we can change the source address of this `ICMP` packet that we are sending out hence spoofing any arbitrary address

![](attachments/Pasted%20image%2020230922155305.png)
Changing `src` to `233.233.233.233` a random ip address gives the follwing result
![](attachments/Pasted%20image%2020230922160123.png)

# Task 1.3 Traceroute

```python
from scapy.all import *
import sys

def traceroute(dest, max_hops=30):
    ttl = 1
    while ttl <= max_hops:
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl}. No reply")
        elif reply.type == 0:
            print(f"{ttl}. {reply.src}")
            break

        elif reply.type == 3:
            if reply.code == 3:
                print(f"{ttl}. {reply.src} - Port unreachable (Destination reached)")
                break
        elif reply.type == 11:  # Time Exceeded
            print(f"{ttl}. {reply.src}")
        else:
            print(f"{ttl}. {reply.src} - Unknown response (Type: {reply.type}, Code: {reply.code})")
            break
        ttl += 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <destination>")
        sys.exit(1)
    dest = sys.argv[1]
    traceroute(dest)

```

The `traceroute` program is mainly made up of a `while` loop that terminates when the `ttl` exceeds the max loop
We slowly increase the `ttl` until a `reply.type==0` is received, which indicates a `echo reply` if a `reply.type==11` is received mean `Time exceeded` we then print out the routing ip increment the `ttl` 
The `ICMP type` is referenced [here](https://www.ibm.com/docs/en/qsip/7.4?topic=applications-icmp-type-code-ids)
## Execution
### Trace route internet
Run `sudo python3 task1-3.py www.google.com` to get the routing information to `www.google.com`
#### Result
![](attachments/Pasted%20image%2020230922165324.png)

### Trace route local
Run `sudo python3 task1-3.py 10.9.0.5` to trace the route to a local machine, which should be completed in one hop
#### Result
![](attachments/Pasted%20image%2020230922165504.png)

# Task 1.4 
```python
from scapy.all import *
def spoof_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		print("Original Packet ...")
		print("Source IP:", pkt[IP].src)
		print("Destination IP:",pkt[IP].dst)
		ip = IP(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl)
		icmp = ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
		data = pkt[Raw].load
		newpkt = ip/icmp/data
		print("spoofed Packet...")
		print("Source IP:", newpkt[IP].src)
		print("Destination IP:",newpkt[IP].dst)
		send(newpkt,verbose=0)
pkt = sniff(iface='br-1714b192a2df', filter='icmp', prn=spoof_pkt)
```
## Execution
Run `sudo python3 task1-4.py` to start sniffing and spooffing on  the host machine (attacker machine) 

carry out the same steps [here](#tcp) to get into a victim machines's shell

## Result 
### 1.2.3.4
Running `ping 1.2.3.4` on the victim machine to a non-exisitent host on the internet, no reply should be expected, but since the attacker machine is spoofing a `ICMP` echo reply to every request, the victim machine will received a reply
![](attachments/Pasted%20image%2020230922225524.png)
![](attachments/Pasted%20image%2020230922225822.png)
We can see from the second screenshot that the ping command is receiving a reply, but from the attacker

### 10.9.0.99
When we attempt to ping an IP address in the LAN, the system first tries to resolve the `MAC address` of the destination IP using the `Address Resolution Protocol (ARP)`. If there's no device with that IP address (10.9.0.99 in this case) on the LAN to answer the ARP request, then `no ARP reply will be received`.
After some time, if the MAC address c`annot be resolved` via ARP, the system understands that it `cannot send the ICMP echo request` to the intended destination, as it doesn't know the hardware (MAC) address of the destination. As a result, it generates an `ICMP error` message indicating that the destination host is unreachable.
Since the networking stack does not know where to send the `ICMP request`, nothing is sent and hence, on the attacker side, nothing is received

![](attachments/Pasted%20image%2020230922225758.png)

### 8.8.8.8
This is a known Google DNS server that is alive. In a typical scenario, the victim machine would receive an `echo reply` from 8.8.8.8. However, due to the attacker machine's `spoofed replies`, the victim machine received two replies - one genuine from 8.8.8.8 and one spoofed by the attacker.
![](attachments/Pasted%20image%2020230922230628.png)
From the result we can see that there are `duplicate replies`
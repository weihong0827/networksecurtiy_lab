#!/usr/bin/env python3
import fcntl
import struct
import os
import time
from scapy.all import *
import select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.54.100/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
# while True:
#     data, (ip, port) = sock.recvfrom(2048)
#     print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
#     pkt = IP(data)
#     print("   Inside: {} --> {}".format(pkt.src, pkt.dst))
# 
#     os.write(tun,bytes(pkt))

SERVER_IP = "10.9.0.5"
os.system("ip route add 192.168.53.0/24 dev tun ")
while True:
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun,bytes(pkt))
        if fd is tun:
            packet = os.read(tun,2048)
            pkt = IP(packet)
            print("From tun    ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (SERVER_IP, PORT))


# Traceroute

import sys
from scapy.all import *

def traceroute(dest, max_hops=30):
    ttl = 1
    while ttl <= max_hops:
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
        # The sr1 function sends the packet and returns the answer
        reply = sr1(pkt, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl}. No reply")
        elif reply.type == 3:  # This is an ICMP Time Exceeded message
            print(f"{ttl}. {reply.src}")
        elif reply.type == 0:  # This is an ICMP Echo Reply message
            print(f"{ttl}. {reply.src} - Reached!")
            break
        else:
            print(f"{ttl}. {reply.src} - Unknown response")
            break

        ttl += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <destination>")
        sys.exit(1)
    dest = sys.argv[1]
    traceroute(dest)

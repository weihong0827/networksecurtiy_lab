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


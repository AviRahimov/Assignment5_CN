from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def send_packet(packet):
    # Send the packet and receive the response
    response = sr1(packet, timeout=2, verbose=False)  # Timeout set to 2 seconds
    # Print the response summary
    if response:
        print(response.summary())
    else:
        print("No response")
    # send(packet)

def spoof_icmp(src_ip, dest_ip):
    # Create an ICMP packet with default values
    icmp_packet = IP(src=src_ip, dst=dest_ip) / ICMP()
    # Send the packet and print the result
    send_packet(icmp_packet)


def spoof_udp(src_ip, dest_ip):
    # Create a UDP packet with custom source port and destination port
    udp_packet = IP(src=src_ip, dst=dest_ip) / UDP(sport=12345, dport=9090)
    # Send the packet and print the result
    send_packet(udp_packet)


def spoof_tcp(src_ip, dest_ip):
    # Create a TCP packet with custom source port, destination port
    tcp_packet = IP(src=src_ip, dst=dest_ip) / TCP(sport=1234, dport=5678)
    # Send the packet and print the result
    send_packet(tcp_packet)


# Usage examples
dest_ip = "10.0.2.15"
src_ip = "1.2.3.4"

# Spoof ICMP packet
spoof_icmp(src_ip, dest_ip)

# Spoof UDP packet
spoof_udp(src_ip, dest_ip)

# Spoof TCP packet
spoof_tcp(src_ip, dest_ip)

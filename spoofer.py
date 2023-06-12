"""
This script demonstrates the sending of spoofed packets using Scapy for ICMP, UDP, and TCP protocols.

Requirements:
- Scapy library must be installed (pip install scapy)

Usage:
1. Modify the 'src_ip' and 'dest_ip' variables to specify the source and destination IP addresses.
2. Run the script to send spoofed packets.

"""

from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def send_packet(packet):
    """
    Send the specified packet.

    @param packet: The packet to send.
    @type packet: scapy.packet.Packet
    """
    send(packet)


def spoof_icmp(src_ip, dest_ip):
    """
    Spoof an ICMP packet by creating an ICMP packet with default values and sending it.

    @param src_ip: The source IP address.
    @type src_ip: str
    @param dest_ip: The destination IP address.
    @type dest_ip: str
    """
    icmp_packet = IP(src=src_ip, dst=dest_ip) / ICMP()
    send_packet(icmp_packet)


def spoof_udp(src_ip, dest_ip):
    """
    Spoof a UDP packet by creating a UDP packet with custom source and destination ports and sending it.

    @param src_ip: The source IP address.
    @type src_ip: str
    @param dest_ip: The destination IP address.
    @type dest_ip: str
    """
    udp_packet = IP(src=src_ip, dst=dest_ip) / UDP(sport=12345, dport=9090)
    send_packet(udp_packet)


def spoof_tcp(src_ip, dest_ip):
    """
    Spoof a TCP packet by creating a TCP packet with custom source and destination ports and sending it.

    @param src_ip: The source IP address.
    @type src_ip: str
    @param dest_ip: The destination IP address.
    @type dest_ip: str
    """
    tcp_packet = IP(src=src_ip, dst=dest_ip) / TCP(sport=1234, dport=5678)
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


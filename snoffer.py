"""
This script demonstrates the usage of the Scapy library to capture and respond to ICMP (Internet Control Message Protocol) packets. It listens for ICMP Echo Request packets and sends corresponding Echo Reply packets as responses.

Requirements:
- Python 3.x
- Scapy library (install with 'pip install scapy')

Usage:
- Run the script with appropriate privileges (e.g., sudo) to capture and send packets.

"""

from scapy.all import *
from scapy.layers.inet import ICMP, IP


def in_cksum(packet):
    """
    Calculate the Internet Checksum of the given packet.

    @param packet: The packet for which to calculate the checksum.
    @type packet: bytes or bytearray
    @return: The calculated checksum.
    @rtype: int
    """
    words = bytes(packet)
    s = 0
    for i in range(0, len(words), 2):
        if i + 1 >= len(words):
            s += words[i]
        else:
            w = words[i] + (words[i + 1] << 8)
            s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def got_packet(packet):
    """
    Process incoming packets and send corresponding response packets.

    @param packet: The incoming packet.
    @type packet: scapy.packet.Packet
    """
    if ICMP in packet and packet[ICMP].type == 8:  # Echo Request
        print("Receive packet From: {}".format(packet[IP].src))
        print("To: {}".format(packet[IP].dst))
        print("------------------------------------------------")

        # Create a response packet
        response_packet = IP(src=packet[IP].dst, dst=packet[IP].src, ihl=packet[IP].ihl, ttl=20) / ICMP(type=0,
                                                                                                        id=packet[
                                                                                                            ICMP].id,
                                                                                                        seq=packet[
                                                                                                            ICMP].seq)

        # Calculate Checksum
        response_packet[ICMP].chksum = in_cksum(bytes(response_packet[ICMP]))

        # Send the response packet
        send(response_packet)


def main():
    """
    Main entry point of the script.
    """
    # The name of the interface as is follows
    iface = "br-d2974611c4aa"

    if iface:
        # Sniff ICMP packets on the chosen interface
        sniff(filter="icmp", prn=got_packet, iface=iface)
    else:
        print(f"No interface named {iface} found")


main()

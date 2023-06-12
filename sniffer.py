"""
This module provides functions to process different types of network packets using the Scapy library.

Requirements:
- scapy
- scapy.contrib.igmp
- scapy.layers.inet

Usage:
1. Import the necessary libraries:
   from scapy.all import *
   from scapy.contrib.igmp import IGMP
   from scapy.layers.inet import ICMP, UDP, TCP, IP

2. Call the `sniff()` function with the desired filter and the packet processing function as parameters:
   sniff(filter="tcp", prn=process_packet)

3. Implement the packet processing functions for different protocols:
   - process_tcp_packet(packet_to_send)
   - process_udp_packet(packet_to_send)
   - process_icmp_packet(packet_to_send)
   - process_igmp_packet(packet_to_send)

4. Use the `processing_packet()` function to extract and process common information from the packets.

Note: The processed packet information is stored in the "SnifferFile.txt" file.

"""

from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import ICMP, UDP, TCP, IP


def process_tcp_packet(packet_to_send):
    """
    Process TCP packets and extract relevant information.

    @param packet_to_send: TCP packet to process.
    """
    processing_packet(TCP, packet_to_send)


def process_udp_packet(packet_to_send):
    """
    Process UDP packets and extract relevant information.

    @param packet_to_send: UDP packet to process.
    """
    processing_packet(UDP, packet_to_send)


def process_icmp_packet(packet_to_send):
    """
    Process ICMP packets and extract relevant information.

    @param packet_to_send: ICMP packet to process.
    """
    processing_packet(ICMP, packet_to_send)


def process_igmp_packet(packet_to_send):
    """
    Process IGMP packets and extract relevant information.

    @param packet_to_send: IGMP packet to process.
    """
    processing_packet(IGMP, packet_to_send)


def processing_packet(protocol, packet_to_send):
    """
    Extract and process common information from the packet.

    @param protocol: Protocol of the packet.
    @param packet_to_send: Packet to process.
    """
    if IP in packet_to_send:
        source_ip = packet_to_send[IP].src
        destination_ip = packet_to_send[IP].dst
        source_port = packet_to_send[protocol].sport
        destination_port = packet_to_send[protocol].dport
        timestamp = packet_to_send.time
        total_length = len(packet_to_send)

        # Extracting the flags and cache control
        flags = packet_to_send[protocol].flags
        # Extracting the cache_control from the first TCP option if available
        options = packet_to_send[protocol].options
        cache_control = options[0][1] if options else 0

        cache_flag = (flags >> 12) & 1
        steps_flag = (flags >> 11) & 1
        type_flag = (flags >> 10) & 1
        status_code = flags & 0x3ff

        # Map the status_code to corresponding text
        if 200 <= status_code < 300:
            status_text = "Success"
        elif 400 <= status_code < 500:
            status_text = "Client Error"
        elif 500 <= status_code < 600:
            status_text = "Server Error"
        else:
            status_text = "Not a response"

        payload = bytes(packet_to_send)
        payload_hex = payload.hex()

        with open("SnifferFile.txt", "a") as file:
            file.write(
                f"{{ source_ip: {source_ip}, dest_ip: {destination_ip}, source_port: {source_port}, dest_port: {destination_port}"
                f", timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, steps_flag: {steps_flag},"
                f" type_flag: {type_flag}, status_code: {status_text}, cache_control: {cache_control}, data: {payload_hex} }}\n")


def process_packet(packet):
    """
    Process the packet based on its protocol.

    @param packet: Packet to process.
    """
    if TCP in packet:
        process_tcp_packet(packet)
    elif UDP in packet:
        process_udp_packet(packet)
    elif ICMP in packet:
        process_icmp_packet(packet)
    elif IGMP in packet:
        process_igmp_packet(packet)


# Sniff network packets and process them using the specified filter and packet processing function
sniff(filter="tcp", prn=process_packet)

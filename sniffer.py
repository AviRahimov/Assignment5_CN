from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import ICMP, UDP, TCP, IP


def process_tcp_packet(packet_to_send):
    """"
    This function as her name says, process TCP packets.
    We extract some information (source_ip, destination_ip...).
    """
    processing_packet(TCP, packet_to_send)


def process_udp_packet(packet_to_send):
    """
    This function as her name says, process UDP packets.
    Overall, this function do as the function above but for UDP protocol
    """
    processing_packet(UDP, packet_to_send)


def process_icmp_packet(packet_to_send):
    """
    This function as her name says, process ICMP packets.
    Overall, this function do as the function above but for ICMP protocol
    """
    processing_packet(ICMP, packet_to_send)


def process_igmp_packet(packet_to_send):
    """
    This function as her name says, process IGMP packets.
    Overall, this function do as the function above but for IGMP protocol
    """
    processing_packet(IGMP, packet_to_send)


def processing_packet(protocol, packet_to_send):
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
    check the protocol type.
    """
    if TCP in packet:
        process_tcp_packet(packet)
    elif UDP in packet:
        process_udp_packet(packet)
    elif ICMP in packet:
        process_icmp_packet(packet)
    elif IGMP in packet:
        process_igmp_packet(packet)


sniff(filter="tcp", prn=process_packet)

"""
Question: Why do you need the root privilege to run a sniffer program? Where does the program fail if it is executed without the root privilege?

Answer: To read raw network packets and record all network traffic on the network interface,
a sniffer software needs root rights. Since it needs full access to the network hardware,
the software wouldn't be able to access the essential low-level network interfaces without these capabilities.
Without root rights, the software would probably not run properly and might not be able to collect every packet on the network interface,
rendering it completely useless. Moreover, it can result in problems relating to access refused, authorization denied, or other issues with insufficient privileges.
"""
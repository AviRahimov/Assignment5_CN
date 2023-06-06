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

        if Raw in packet_to_send:
            cache_flag = packet_to_send[Raw].load
        else:
            cache_flag = b''  # Set a default value or handle it according to your requirements

        # Modify or replace with appropriate values for the following flags
        steps_flag = ""
        type_flag = ""
        status_code = ""
        cache_control = ""

        if hasattr(packet_to_send.payload, 'hexdump'):  # Check if hexdump method is available
            payload_hex = packet_to_send.payload.hexdump()  # Use hexdump instead of hex
        else:
            payload_hex = ''  # Set a default value or handle it according to your requirements
        with open("SnifferFile.txt", "a") as file:
            file.write(
                f"{{ source_ip: {source_ip}, dest_ip: {destination_ip}, source_port: {source_port}, dest_port: {destination_port}"
                f", timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag.hex()}, steps_flag: {steps_flag},"
                f" type_flag: {type_flag}, status_code: {status_code}, cache_control: {cache_control}, data: {payload_hex} }}\n")

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

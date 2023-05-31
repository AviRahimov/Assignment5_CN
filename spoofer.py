import socket
import struct
import random


def calculate_checksum(packet) -> int:
    """
    Calculates the checksum of the packet.
    :param packet: Packet to calculate checksum for
    :return: Calculated checksum
    """
    checksum = 0
    count_to = (len(packet) // 2) * 2
    for i in range(0, count_to, 2):
        checksum += (packet[i] << 8) + packet[i + 1]
    if count_to < len(packet):
        checksum += packet[len(packet) - 1] << 8
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return (~checksum) & 0xFFFF


def send_raw_ip_packet(protocol_type, ip_header, dest_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(ip_header, (dest_ip, 0))
        s.close()
        print(f"Packet sent successfully on {protocol_type} protocol!")
    except PermissionError:
        print("Error: Permission denied. Try running the script with administrator privileges.")


def spoof_icmp(dest_ip):
    icmp_type = 8  # ICMP Type 8 is request, 0 is reply
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = random.randint(0, 65535)
    icmp_seq = 1

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_checksum = calculate_checksum(icmp_header)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 28, 54321, 0, 64, 1, 0, socket.inet_aton("1.2.3.4"),
                            socket.inet_aton(dest_ip))
    packet = ip_header + icmp_header

    send_raw_ip_packet("ICMP", packet, dest_ip)


def spoof_udp(dest_ip):
    udp_source_port = 12345
    udp_dest_port = 9090
    udp_length = 8  # UDP header length
    udp_checksum = 0

    udp_header = struct.pack("!HHHH", udp_source_port, udp_dest_port, udp_length, udp_checksum)

    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(udp_header), 54321, 0, 64, 17, 0,
                            socket.inet_aton("1.2.3.4"), socket.inet_aton(dest_ip))
    packet = ip_header + udp_header

    send_raw_ip_packet("UDP", packet, dest_ip)


def spoof_tcp(dest_ip):
    tcp_source_port = 1234
    tcp_dest_port = 5678
    tcp_seq = 0
    tcp_ack = 13
    tcp_offset = (5 << 4)  # TCP header length and reserved bits
    tcp_flags = 0x018  # SYN and ACK flags
    tcp_window = 2000
    tcp_checksum = 0

    tcp_header = struct.pack("!HHLLBBHHH", tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack, tcp_offset, tcp_flags,
                             tcp_window, tcp_checksum, 0)

    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton("10.0.2.15"), socket.inet_aton(dest_ip), 0,
                                socket.IPPROTO_TCP, len(tcp_header))
    pseudo_header_checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_checksum = pseudo_header_checksum

    tcp_header = struct.pack("!HHLLBBH", tcp_source_port, tcp_dest_port, tcp_seq, tcp_ack, tcp_offset, tcp_flags,
                             tcp_window) + struct.pack('H', tcp_checksum)

    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(tcp_header), 54321, 0, 64, 6, 0,
                            socket.inet_aton("10.0.2.15"), socket.inet_aton(dest_ip))
    packet = ip_header + tcp_header

    send_raw_ip_packet("TCP", packet, dest_ip)


# Usage examples
dest_ip = "10.0.2.15"

# Spoof ICMP packet
spoof_icmp(dest_ip)

# Spoof UDP packet
spoof_udp(dest_ip)

# Spoof TCP packet
spoof_tcp(dest_ip)

"""
Question 1: Can you set the IP packet length field to an arbitrary value, regardless of how big the actual packet is?

Answer: No, you cannot set the IP packet length field to an arbitrary value, regardless of how big the actual packet is.
The IP packet length field must match the actual size of the packet,
otherwise it will be rejected by the receiver or an intermediate router.

_______________________________________________________________________________________________________________________

Question 2:Using the raw socket programming, do you have to calculate the checksum for the IP header?

Answer: Yes, The checksum for the IP header must typically be calculated manually when using raw socket programming.
When using higher-level socket APIs, the operating system's network stack often handles checksum computations for
outgoing packets automatically.
But, you have more control over the packet construction—including the IP header—with raw sockets.
"""

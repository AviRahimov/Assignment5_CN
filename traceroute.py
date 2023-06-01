import socket
import struct
import sys


def checksum(data):
    # calculate the checksum for the ICMP packet
    sum = 0
    for i in range(0, len(data), 2):
        sum += (data[i] << 8) + data[i + 1]
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff


def traceroute(dest_name):
    # perform a traceroute to the destination name
    dest_addr = socket.gethostbyname(dest_name)  # get the destination IP address
    icmp = socket.getprotobyname('icmp')  # get the ICMP protocol number
    ttl = 1  # initialize the TTL value
    max_hops = 30  # maximum number of hops
    while True:
        # create a raw socket for sending and receiving ICMP packets
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        # set the TTL value of the send socket
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        # bind the receive socket to any available port
        recv_socket.bind(("", 0))
        # create an ICMP echo request packet with a dummy payload
        icmp_type = 8  # echo request type
        icmp_code = 0  # echo request code
        icmp_id = 0  # identifier
        icmp_seq = ttl  # sequence number
        icmp_checksum = 0  # checksum (initially zero)
        payload = b"Hello World!"  # dummy payload
        packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id,
                             icmp_seq) + payload  # pack the header and payload
        icmp_checksum = checksum(packet)  # calculate the checksum
        packet = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id,
                             icmp_seq) + payload  # pack the header and payload with checksum
        # send the packet to the destination address
        send_socket.sendto(packet, (dest_addr, 0))
        curr_addr = None  # initialize the current address
        try:
            # receive a packet from any source address and port
            data, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]  # get the source IP address
            # unpack the IP header and get the protocol number
            ip_header = data[:20]
            ip_protocol = ip_header[9]
            # unpack the ICMP header and get the type and code
            icmp_header = data[20:28]
            icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])
        except socket.error:
            pass  # ignore socket errors
        finally:
            # close the sockets
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            # print the hop number and source IP address
            print("%d\t%s" % (ttl, curr_addr))

        ttl += 1  # increment the TTL value

        if curr_addr == dest_addr or ttl > max_hops or icmp_type == 3:
            break  # stop if reached destination or maximum hops or received an ICMP destination unreachable message


if __name__ == "__main__":
    traceroute("172.217.17.46")  # call traceroute with a destination name or IP address

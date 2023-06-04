from scapy.all import *
from scapy.layers.inet import ICMP, IP

class TracerouteError(Exception):
    pass

def traceroute(destination):
    """
    Perform a traceroute to the specified destination IP address.

    Parameters:
        destination (str): The IP address or hostname of the destination.

    Returns:
        None

    Raises:
        KeyboardInterrupt: If the traceroute is interrupted by the user.
        TracerouteError: If an error occurs during the traceroute.
    """

    ttl = 1
    max_hops = 30  # Maximum number of hops to try

    try:
        print("Start sending an icmp_packet...")
        while True:
            # Create the IP packet with the current TTL
            icmp_packet = IP(dst=destination, ttl=ttl) / ICMP()

            try:
                # Send the packet and wait for the response
                reply = sr1(icmp_packet, verbose=0, timeout=1)

                if reply is None:
                    # No response received within the timeout, so print an error message
                    print(f"{ttl}. * * * Request timed out.")

                elif reply.type == 11 and reply.code == 0:
                    # ICMP Time Exceeded message received, print the IP address of the router
                    print(f"{ttl}. {reply.src}")

                    if reply.src == destination:
                        # Destination reached, so break the loop
                        break

                elif reply.type == 0:
                    # ICMP Echo Reply message received, print the IP address of the destination
                    print(f"{ttl}. {reply.src} Destination reached.")
                    break

                else:
                    # Unexpected response received, print an error message
                    print(f"{ttl}. * * * Unexpected response received.")

            except Exception as e:
                # Handle Scapy-related exceptions
                raise TracerouteError(f"Error occurred during traceroute: {str(e)}")

            ttl += 1

            if ttl > max_hops:
                # Maximum number of hops exceeded, break the loop
                break

    except KeyboardInterrupt:
        # Traceroute interrupted by the user
        raise KeyboardInterrupt


# Usage example
destination_ip = "www.google.com"
traceroute(destination_ip)

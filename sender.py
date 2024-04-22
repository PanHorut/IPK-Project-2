# Testing script for IPK Network Sniffer

from scapy.all import Raw, sr1, IP, TCP, UDP, send, sendp, Ether, ARP, IPv6, ICMPv6EchoRequest, ICMP, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6MLQuery

def send_tcp_packet():
    # Creating the TCP packet with destination port 832
    packet = IP(dst="127.0.0.1") / TCP(dport=832, sport=24, flags='S') / "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    
    # Sending the packet through the loopback interface
    send(packet, iface='lo')

def send_arp_request(destination_ip, interface="wlp2s0", count=1):
    # Craft ARP request packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=destination_ip)  # op=1 for ARP request

    # Send the packet
    for _ in range(count):
        sendp(packet, iface=interface)

def send_icmp6_packet(destination, interface="lo", count=1):
    # Craft ICMPv6 echo request packet
    packet = IPv6(dst=destination) / ICMPv6EchoRequest()

    # Send the packet
    for _ in range(count):
        send(packet, iface=interface)

def send_ndp_packet(target_ip, target_mac, interface="wlp2s0", count=1):
    # Craft NDP Neighbor Solicitation packet
    packet = Ether(dst=target_mac) / IPv6(dst=target_ip) / ICMPv6ND_NS(tgt=target_ip) / ICMPv6NDOptSrcLLAddr()

    # Send the packet
    for _ in range(count):
        sendp(packet, iface=interface)
        
def send_mld_packet(destination, interface="wlp2s0", count=1):
    # Craft MLD Multicast Listener Query packet
    packet = Ether() / IPv6(dst=destination) / ICMPv6MLQuery()

    # Send the packet
    for _ in range(count):
        sendp(packet, iface=interface)

def send_udp_packet(destination_ip, destination_port=84, source_port=54321, interface="wlp2s0", count=1):
    # Craft UDP packet
    packet = IP(dst=destination_ip) / UDP(dport=destination_port, sport=source_port)

    # Send the packet
    for _ in range(count):
        send(packet, iface=interface)
        
def send_icmpv4_packet():
    packet = IP(dst="127.0.0.1") / ICMP()
    send(packet)

# Example usage
if __name__ == "__main__":
    send_tcp_packet()
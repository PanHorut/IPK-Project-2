#ifndef SNIFFER_HPP
#define SNIFFER_HPP

#include <iostream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <sstream>
#include <csignal>
#include <vector>

// For time format
#include <iomanip>
#include <ctime>   

// Packet and exception
#include "packet.hpp"
#include "exception.hpp"

/**
 * @brief The Sniffer class provides functionality for sniffing network packets.
 * 
 * The Sniffer class is responsible for capturing and processing network packets.
 */
class Sniffer{
    public:
        /**
         * @brief Constructor for the Sniffer class.
         */
        Sniffer();

        /**
         * @brief Processes the IPv4 packet.
         * 
         * This method is responsible for processing the IPv4 packet and extracting relevant information.
         * 
         * @param iph Pointer to the ip struct representing the IPv4 header.
         * @param packet Reference to the Packet object to store the extracted information.
         * @param packetptr Pointer to the start of the packet data.
         */
        static void process_ipv4(struct ip *iph, Packet& packet, const u_char *packetptr);

        /**
         * @brief Processes the IPv6 packet.
         * 
         * This method is responsible for processing the IPv6 packet and extracting relevant information.
         * 
         * @param ip6h Pointer to the ip6_hdr struct representing the IPv6 header.
         * @param packet Reference to the Packet object to store the extracted information.
         * @param packetptr Pointer to the start of the packet data.
         */
        static void process_ipv6(struct ip6_hdr *ip6h, Packet& packet, const u_char *packetptr);

        /**
         * @brief Processes the ARP packet.
         * 
         * This method is responsible for processing the ARP packet and extracting relevant information.
         * 
         * @param arp Pointer to the ether_arp struct representing the ARP header.
         * @param packet Reference to the Packet object to store the extracted information.
         */
        static void process_arp(ether_arp *arp, Packet& packet);

        /**
         * @brief Processes the TCP packet.
         * 
         * This method is responsible for processing the TCP packet and extracting relevant information.
         * 
         * @param packetptr Pointer to the start of the packet data.
         * @param packet Reference to the Packet object to store the extracted information.
         */
        static void process_tcp(const u_char *packetptr, Packet& packet);

        /**
         * @brief Processes the UDP packet.
         * 
         * This method is responsible for processing the UDP packet and extracting relevant information.
         * 
         * @param packetptr Pointer to the start of the packet data.
         * @param packet Reference to the Packet object to store the extracted information.
         */
        static void process_udp(const u_char *packetptr, Packet& packet);

        /**
         * @brief Processes the ICMP packet.
         * 
         * This method is responsible for processing the ICMP packet and extracting relevant information.
         * 
         * @param packetptr Pointer to the start of the packet data.
         * @param packet Reference to the Packet object to store the extracted information.
         */
        static void process_icmp(const u_char *packetptr, Packet& packet);

        /**
         * @brief Reads a line of content from the packet data at the specified offset.
         * 
         * This method reads a line of content from the packet data at the specified offset.
         * 
         * @param packetptr Pointer to the start of the packet data.
         * @param content Reference to the string to store the read content.
         * @param offset The offset in the packet data to start reading from.
         * @param len_to_read The length of the content to read.
         * @param packet Reference to the Packet object to store the extracted information.
         * @return The line of content read from the packet data.
         */
        static std::string read_offset_line(const u_char *packetptr, std::string& content, int offset, int len_to_read,Packet& packet);

        /**
         * @brief Reads the content from the packet data.
         * 
         * This method reads the content from the packet data.
         * 
         * @param packetptr Pointer to the start of the packet data.
         * @param length The length of the content to read.
         * @param packet Reference to the Packet object to store the extracted information.
         * @return The content read from the packet data.
         */
        static std::string read_content(const u_char *packetptr, int length, Packet& packet);

        /**
         * @brief Checks if a character is printable.
         * 
         * This method checks if a character is printable.
         * 
         * @param c The character to check.
         * @return True if the character is printable, false otherwise.
         */
        static bool isPrintable(char c);

        /**
         * @brief Converts a nibble to its hexadecimal representation.
         * 
         * This method converts a nibble to its hexadecimal representation.
         * 
         * @param nibble The nibble to convert.
         * @return The hexadecimal representation of the nibble.
         */
        static char nibbleToHex(unsigned char nibble);

        /**
         * @brief Packet processor function for pcap_loop.
         * 
         * This function is used as the packet processor for pcap_loop.
         * It is responsible for processing each captured packet.
         * 
         * @param user User-defined data passed to pcap_loop.
         * @param pkthdr Pointer to the pcap_pkthdr struct representing the packet header.
         * @param packet Pointer to the start of the packet data.
         */
        static void packet_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

        /**
         * @brief Initializes the sniffer with the specified interface, filter, and packet count.
         * 
         * This method initializes the sniffer with the specified interface, filter, and packet count.
         * 
         * @param interface The network interface to sniff on.
         * @param filter The filter expression to apply to captured packets.
         * @param count The maximum number of packets to capture.
         */
        void init_sniffer(std::string interface, std::string filter, int count);

        /**
         * @brief Starts the sniffing process using the specified pcap handle and packet count.
         * 
         * This method starts the sniffing process using the specified pcap handle and packet count.
         * 
         * @param handle The pcap handle to use for capturing packets.
         * @param count The maximum number of packets to capture.
         */
        void start_sniffing(pcap_t* handle, int count);

        /**
         * @brief The link type of the captured packets.
         */
        static int linktype;

};

#endif
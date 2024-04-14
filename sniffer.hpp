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

#include <sstream>
#include <csignal>

// For time format
#include <iomanip>
#include <ctime>   

// Packet
#include "packet.hpp"

class Sniffer{
    public:
        Sniffer();

        static void process_tcp(const u_char *packetptr, Packet& packet);

        static void process_udp(const u_char *packetptr, Packet& packet);

        static void process_icmp(const u_char *packetptr, Packet& packet);

        static std::string read_offset_line(const u_char *packetptr, std::string& content, int offset, int len_to_read = 16);

        static std::string read_content(const u_char *packetptr, int length);

        static bool isPrintable(char c);

        static char nibbleToHex(unsigned char nibble);

        static void packet_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

        void init_sniffer(std::string interface, std::string filter, int count);

        void start_sniffing(pcap_t* handle, int count);

        static int linktype;

};

#endif
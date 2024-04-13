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

// For time format
#include <iomanip>
#include <ctime>   

class Sniffer{
    public:
        Sniffer();

        static void packet_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

        void init_sniffer(std::string interface, std::string filter, int count);

        void start_sniffing(pcap_t* handle, int count);

};

#endif
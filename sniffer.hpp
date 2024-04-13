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

class Sniffer{
    public:
        Sniffer();
        void start_sniffing(std::string interface, std::string filter);


};

#endif
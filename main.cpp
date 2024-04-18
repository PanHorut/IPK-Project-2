#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "sniffer.hpp"
#include "tools.hpp"


int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = NULL;


    ArgParser argParser(argc, argv);
    argParser.parse_arguments();

    if(argParser.get_interface() == ""){

        if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return 1;
        }

        std::cout << "Available interfaces:" << std::endl;
        for (pcap_if_t* device = devices; device; device = device->next) {
            std::cout << device->name << std::endl;
        }

    } else {
        Sniffer sniffer;
        sniffer.init_sniffer(argParser.get_interface(), argParser.get_filter(), argParser.get_count());
    }
    return 0;
}
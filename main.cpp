/**
 * @file   main.cpp
 * @brief  Main
 * @author Dominik Horut (xhorut01)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>

#include "sniffer.hpp"
#include "tools.hpp"
#include "exception.hpp"

int main(int argc, char* argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = NULL;

    ArgParser argParser(argc, argv);

    try{
        /// Parse arguments
        argParser.parse_arguments();

    }catch(const std::exception& e) {
        std::cout << "Argument error: " << e.what() << std::endl;
        return 1;
    }

    /// Print all available interfaces if no interface is provided by user
    if(argParser.get_interface() == ""){

        if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
            return 1;
        }

        std::cout << "Available interfaces:" << std::endl;
        for (pcap_if_t* device = devices; device; device = device->next) {
            std::cout << device->name << std::endl;
        }

        pcap_freealldevs(devices);

    /// Sniff for desired packets
    } else {
        Sniffer sniffer;

        try{
            sniffer.init_sniffer(argParser.get_interface(), argParser.get_filter(), argParser.get_count());

        } catch(const std::exception& e) {
            std::cerr << "Sniffer error: " << e.what() << std::endl;
            return 1;
        }
    }
    return 0;
}
#include "sniffer.hpp"

Sniffer::Sniffer() {}

void Sniffer::start_sniffing(std::string interface, std::string filter){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    if (pcap_lookupnet(interface.c_str(), &srcip, &netmask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        return;
    }
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <iostream>


int main(int argc, char* argv[]) {
    char device[256];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices = NULL;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    pcap_t *handle = NULL;
    struct bpf_program bpf;

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    strcpy(device, devices[0].name);

    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return 1;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return 1;
    }


    return 0;
}
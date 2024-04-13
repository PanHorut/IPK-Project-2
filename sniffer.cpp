#include "sniffer.hpp"

Sniffer::Sniffer() {}

void Sniffer::init_sniffer(std::string interface, std::string filter, int count){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    if (pcap_lookupnet(interface.c_str(), &srcip, &netmask, errbuf) == -1) {
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
        return;
    }

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return;
    }

    int linktype;
 
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }

    if(linktype != DLT_EN10MB && linktype != DLT_LINUX_SLL){
        fprintf(stderr, "Only Ethernet interfaces are supported.\n");
        return;
    }   

    if (pcap_compile(handle, &bpf, filter.c_str(), 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return;
    }

    start_sniffing(handle, count);
}

void Sniffer::start_sniffing(pcap_t* handle, int count){

    if (pcap_loop(handle, count, &packet_processor, (u_char*)NULL) < 0) {
    	fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
	    return;
    }
}

void Sniffer::packet_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
     // Extract timestamp from pcap_pkthdr structure
    struct timeval timestamp = pkthdr->ts;

    // Convert timestamp to time_t
    time_t time = timestamp.tv_sec;

    // Convert time_t to UTC time struct
    std::tm *gmt_tm = std::gmtime(&time);

    // Format timestamp in RFC 3339 format
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%T%z", gmt_tm);

    // Print timestamp
    std::cout << "Packet captured at: " << buffer << std::endl;

    // Process the rest of the packet as needed
}

#include "sniffer.hpp"

Sniffer::Sniffer() {}
Packet::Packet() {}

int Sniffer::linktype;

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
    pcap_freecode(&bpf);

    start_sniffing(handle, count);

    pcap_close(handle);
}

void Sniffer::start_sniffing(pcap_t* handle, int count){

    if (pcap_loop(handle, count, &packet_processor, (u_char*)NULL) < 0) {
    	fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
	    return;
    }

    
}

void Sniffer::packet_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetptr) {
    
    Packet packet;

    // get timestamp
    struct timeval timestamp = pkthdr->ts;
    time_t time = timestamp.tv_sec;
    std::tm *gmt_tm = std::gmtime(&time);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%T%z", gmt_tm);
    packet.set_timestamp(std::string(buffer));

    // get mac address and print it
    struct ether_header *eth = (struct ether_header *)packetptr;
    packet.set_src_mac(ether_ntoa((const struct ether_addr *)&eth->ether_shost));
    packet.set_dst_mac(ether_ntoa((const struct ether_addr *)&eth->ether_dhost));
    packet.set_src_mac(Packet::format_mac(packet.src_mac));
    packet.set_dst_mac(Packet::format_mac(packet.dst_mac));

    // get frame length and print it
    packet.set_frame_len(pkthdr->len);

    uint16_t ether_type = ntohs(eth->ether_type);
    
    if(ether_type == ETHERTYPE_IP){

        struct ip *iph = (struct ip *)(packetptr + sizeof(struct ether_header));
        process_ipv4(iph, packet, packetptr);
    
    }else if (ether_type == ETHERTYPE_IPV6){

        struct ip6_hdr *ip6h = (struct ip6_hdr *)(packetptr + sizeof(struct ether_header));
        process_ipv6(ip6h, packet, packetptr);

    }else if (ether_type == ETHERTYPE_ARP){

        struct arphdr *arp_hdr = (struct arphdr *)(packetptr + sizeof(struct ether_header));
        //process_arp(packetptr, packet);

    }else{
        // Something is wrong if this happens
    }
    //packetptr -= 34;
    int content_len = pkthdr->len;
    std::string content = Sniffer::read_content(packetptr, content_len);
    packet.set_byte_offset(content);
    packet.print_packet(packet);

}

void Sniffer::process_ipv4(struct ip *iph, Packet& packet, const u_char *packetptr){

    // Setting IP addresses
    packet.set_src_ip(std::string(inet_ntoa(iph->ip_src)));
    packet.set_dst_ip(std::string(inet_ntoa(iph->ip_dst)));
    
    // 14 is size of ethernet header
    packetptr += (iph->ip_hl * 4) + 14;
    
    switch(iph->ip_p){
        case IPPROTO_TCP:{
            Sniffer::process_tcp(packetptr, packet);
            break;
        }
        case IPPROTO_UDP:{
            Sniffer::process_udp(packetptr, packet);
            break;
        }
        case IPPROTO_ICMP:{
            Sniffer::process_icmp(packetptr, packet);
            break;
        }
        
    }
}

void Sniffer::process_ipv6(struct ip6_hdr *ip6h, Packet& packet, const u_char *packetptr){

    // Setting IP addresses
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6h->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
    packet.set_src_ip(std::string(src_ip));
    packet.set_dst_ip(std::string(dst_ip));

}


void Sniffer::process_tcp(const u_char *packetptr, Packet& packet){
    struct tcphdr* tcphdr = (struct tcphdr*)packetptr;
    packet.set_src_port(ntohs(tcphdr->th_sport));
    packet.set_dst_port(ntohs(tcphdr->th_dport));

}

void Sniffer::process_udp(const u_char *packetptr, Packet& packet){
    struct udphdr* udphdr = (struct udphdr*)packetptr;
    packet.set_src_port(ntohs(udphdr->uh_sport));
    packet.set_dst_port(ntohs(udphdr->uh_dport));
}

void Sniffer::process_icmp(const u_char *packetptr, Packet& packet){
    struct icmphdr* icmphdr = (struct icmphdr*)packetptr;
    packet.set_src_port(0);
    packet.set_dst_port(0);
}

std::string Sniffer::read_content(const u_char *packetptr, int length){
    std::string content = "\n";
    int offset = 0;
    int len_to_read;   
    while(0 < length){
        if(length < 16){
            len_to_read = length;

        }else{
            len_to_read = 16;
        }

        content = read_offset_line(packetptr, content, offset, len_to_read);
        content.append("\n");   
        length -= len_to_read;
        offset += 16;
        
    }
    
    return content;
}

std::string Sniffer::read_offset_line(const u_char *packetptr, std::string& content, int offset, int len_to_read){
    
    for (int i = 0; i < len_to_read; i++){
        unsigned char c = (unsigned char) packetptr[i + offset];
    
        content.push_back(nibbleToHex((c >> 4) & 0xF)); // High nibble
        content.push_back(nibbleToHex(c & 0xF)); 
        content.append(" ");
    
    }

    content.append(" ");
    
    for (int i = 0; i < len_to_read; i++){
        unsigned char c = (unsigned char) packetptr[i + offset];
        if(i == 8)
            content.append(" ");
        if(isPrintable(c))
            content.push_back(c);
        else
            content.push_back('.');
    
    }
    return content;
}

bool Sniffer::isPrintable(char c) {
    return (c >= 32 && c <= 126);
}

char Sniffer::nibbleToHex(unsigned char nibble) {
    if (nibble < 10) {
        return '0' + nibble; // Digits '0' to '9'
    } else {
        return 'a' + (nibble - 10); // Letters 'A' to 'F'
    }
}

std::string Packet::format_mac(std::string mac){
    std::string formatted_mac = ""; 
    std::vector<std::string> tokens;
    std::stringstream ss(mac);

    // Temporary string to hold each token
    std::string token;

    // Tokenize the string using ':' as delimiter
    while (std::getline(ss, token, ':')) {
        tokens.push_back(token);
    }

    // Print the tokens
    for (auto& t : tokens) {
        if(t == "0"){
            formatted_mac += "00:";   
        }else{
            formatted_mac += t + ":";   
        }
    }
    return formatted_mac.substr(0, formatted_mac.size() - 1);
}

void Packet::print_packet(Packet packet){
    std::cout << "timestamp: " << timestamp << std::endl;
    std::cout << "src MAC: " << src_mac << std::endl;
    std::cout << "dst MAC: " << dst_mac << std::endl;
    std::cout << "frame length: " << frame_len << std::endl;
    std::cout << "src IP: " << src_ip << std::endl;
    std::cout << "dst IP: " << dst_ip << std::endl;
    std::cout << "src port: " << src_port << std::endl;
    std::cout << "dst port: " << dst_port << std::endl;
    std::cout << byte_offset << std::endl;
}

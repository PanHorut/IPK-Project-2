#include "sniffer.hpp"

Sniffer::Sniffer() {}
Packet::Packet() {}

int Sniffer::linktype;

pcap_t* global_handle;

void sigint_handler(int signal) {
    pcap_close(global_handle);  
    exit(0);      
}

void Sniffer::init_sniffer(std::string interface, std::string filter, int count){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;
    
    std::signal(SIGINT, sigint_handler);

    if (pcap_lookupnet(interface.c_str(), &srcip, &netmask, errbuf) == -1) {
        throw SnifferException("Invalid interface");
        return;
    }

    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    global_handle = handle;

    if (handle == NULL) {
        throw SnifferException("Error when opening interface");
        return;
    }
 
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        pcap_close(handle);
        throw SnifferException("Error when getting link header");
        return;
    }
    
    if(linktype != DLT_EN10MB && linktype != DLT_LINUX_SLL && linktype != DLT_NULL){
        pcap_close(handle);
        throw SnifferException("Only ethernet is supported");
        return;
    }   

    if (pcap_compile(handle, &bpf, filter.c_str(), 0, netmask) == PCAP_ERROR) {
        pcap_close(handle);
        throw SnifferException("Invalid pcap compilation");
        return;
    }

    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        pcap_close(handle);
        pcap_freecode(&bpf);
        throw SnifferException("Error when setting filter");
        return;
    }
    pcap_freecode(&bpf);

    start_sniffing(handle, count);

    pcap_close(handle);
}

void Sniffer::start_sniffing(pcap_t* handle, int count){

    if (pcap_loop(handle, count, &packet_processor, (u_char*)NULL) < 0) {
        pcap_close(handle);
    	throw SnifferException("Pcap loop failed");
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

    }else if (ether_type == ETHERTYPE_ARP) {
    // Handle ARP frames
        struct ether_arp *arp = (struct ether_arp *)(packetptr + sizeof(struct ether_header));
        process_arp(arp, packet);
    }else{
        throw SnifferException("Unexpected ether type");
    }

    int content_len = pkthdr->len;
    std::string content = Sniffer::read_content(packetptr, content_len, packet);
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
    packet.set_src_port(0);
    packet.set_dst_port(0);

}

void Sniffer::process_arp(ether_arp *arp, Packet& packet){

    struct in_addr src_ip_addr, dst_ip_addr;
    memcpy(&src_ip_addr, arp->arp_spa, sizeof(src_ip_addr));
    memcpy(&dst_ip_addr, arp->arp_tpa, sizeof(dst_ip_addr));

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_ip_addr, dst_ip_str, INET_ADDRSTRLEN);

    packet.set_src_ip(src_ip_str);
    packet.set_dst_ip(dst_ip_str);

    packet.set_src_port(0);
    packet.set_dst_port(0);
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
    //struct icmphdr* icmphdr = (struct icmphdr*)packetptr;
    packet.set_src_port(0);
    packet.set_dst_port(0);
}

std::string Sniffer::read_content(const u_char *packetptr, int length, Packet& packet){
    std::string content = "\n";
    int offset = 0;
    int len_to_read;   
    while(0 < length){
        if(length < 16){
            len_to_read = length;

        }else{
            len_to_read = 16;
        }

        content = read_offset_line(packetptr, content, offset, len_to_read, packet);
        content.append("\n");   
        length -= len_to_read;
        offset += 16;
        
    }
    
    return content;
}

std::string Sniffer::read_offset_line(const u_char *packetptr, std::string& content, int offset, int len_to_read, Packet& packet){
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(4) << packet.content_len;
    content.append(ss.str() + ": ");
    packet.content_len += 16;

    for (int i = 0; i < len_to_read; i++){
        unsigned char c = (unsigned char) packetptr[i + offset];
    
        content.push_back(nibbleToHex((c >> 4) & 0xF)); // High nibble
        content.push_back(nibbleToHex(c & 0xF)); 
        content.append(" ");
    
    }

    if(len_to_read != 16){
    
        int i = (16 - len_to_read)*3;
        while(i){
           
            content.append(" ");
          
            i--;
        }
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

    std::string token;

    while (std::getline(ss, token, ':')) {
        tokens.push_back(token);
    }

    for (auto& t : tokens) {
        if(t == "0"){
            formatted_mac += "00:";   
        }else if(t == "1"){
            formatted_mac += "01:";   
        }else if(t == "2"){
            formatted_mac += "02:";   
        }else if(t == "3"){
            formatted_mac += "03:";   
        }else if(t == "4"){
            formatted_mac += "04:";   
        }else if(t == "5"){
            formatted_mac += "05:";   
        }else if(t == "6"){
            formatted_mac += "06:";   
        }else if(t == "7"){
            formatted_mac += "07:";   
        }else if(t == "8"){
            formatted_mac += "08:";   
        }else if(t == "9"){
            formatted_mac += "09:";   
        }else if(t == "a"){
            formatted_mac += "0a:";   
        }else if(t == "b"){
            formatted_mac += "0b:";   
        }else if(t == "c"){
            formatted_mac += "0c:";   
        }else if(t == "d"){
            formatted_mac += "0d:";   
        }else if(t == "e"){
            formatted_mac += "0e:";   
        }else if(t == "f"){
            formatted_mac += "0f:";   
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

    if(src_ip == ""){
        src_ip = "-";
    }

    if(dst_ip == ""){
        dst_ip = "-";
    }
    
    std::cout << "src IP: " << src_ip << std::endl;
    std::cout << "dst IP: " << dst_ip << std::endl;

    if(src_port == 0){
        std::cout << "src port: -" << std::endl;
    }else{
        std::cout << "src port: " << src_port << std::endl;
    }

    if(dst_port == 0){
        std::cout << "dst port: -" << std::endl;
    }else{
        std::cout << "dst port: " << dst_port << std::endl;
    }
    std::cout << byte_offset << std::endl;
}

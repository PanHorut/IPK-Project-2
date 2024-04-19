#ifndef PACKET_HPP
#define PACKET_HPP

#include <string>
#include <string.h>
#include <netinet/in.h>

/**
 * @brief The Packet class represents a network packet.
 * 
 * This class provides methods to set and retrieve various properties of a packet.
 * It also provides a method to format MAC addresses and a method to print the packet.
 */
class Packet{
    private:
        std::string timestamp = ""; 
        int frame_len = 0;
        std::string src_ip;
        std::string dst_ip; 
        std::string byte_offset = "";

    public:
        u_int16_t src_port;
        u_int16_t dst_port;
        std::string src_mac;
        std::string dst_mac;

        /// Content line number
        int content_len = 0x0000;

        /**
         * @brief Constructor for the Packet class.
         */
        Packet();

        /**
         * @brief Sets the timestamp of the packet.
         * @param timestamp The timestamp to set.
         */
        void set_timestamp(std::string timestamp);

        /**
         * @brief Sets the source MAC address of the packet.
         * @param src_mac The source MAC address to set.
         */
        void set_src_mac(std::string src_mac);

        /**
         * @brief Sets the destination MAC address of the packet.
         * @param dst_mac The destination MAC address to set.
         */
        void set_dst_mac(std::string dst_mac);

        /**
         * @brief Sets the frame length of the packet.
         * @param frame_len The frame length to set.
         */
        void set_frame_len(int frame_len);
        
        /**
         * @brief Sets the source IP address of the packet.
         * @param src_ip The source IP address to set.
         */
        void set_src_ip(std::string src_ip);

        /**
         * @brief Sets the destination IP address of the packet.
         * @param dst_ip The destination IP address to set.
         */
        void set_dst_ip(std::string dst_ip);

        /**
         * @brief Sets the source port of the packet.
         * @param src_port The source port to set.
         */
        void set_src_port(u_int16_t src_port);

        /**
         * @brief Sets the destination port of the packet.
         * @param dst_port The destination port to set.
         */
        void set_dst_port(u_int16_t dst_port);

        /**
         * @brief Sets the byte offset of the packet.
         * @param byte_offset The byte offset to set.
         */
        void set_byte_offset(std::string byte_offset);    

        /**
         * @brief Formats a MAC address.
         * @param mac The MAC address to format.
         * @return The formatted MAC address.
         */
        static std::string format_mac(std::string mac);
    
        /**
         * @brief Prints the packet.
         * @param packet The packet to print.
         */
        void print_packet(Packet packet);

};

#endif
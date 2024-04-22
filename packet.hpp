#ifndef PACKET_HPP
#define PACKET_HPP

/**
 * @file   packet.hpp
 * @brief  Header file for packet representation 
 * @author Dominik Horut (xhorut01)
 */

#include <string>
#include <string.h>
#include <netinet/in.h>


/**
 * @class Class representing packet.
 * 
 * @brief Provides setting packet attributes and printing packet information
*/
class Packet{
    private:
        std::string timestamp = "";
        int frame_len = 0;
        std::string src_ip;
        std::string dst_ip;
        std::string byte_offset = "";
        std::string type= "";

    public:

        u_int16_t src_port;
        u_int16_t dst_port;
        std::string src_mac;
        std::string dst_mac;

        /// Payload line counter
        int content_len = 0x0000;

        /// @brief Constructor of packet instance
        Packet();

        /**
         * @brief Setter of timestamp
         * @param timestamp timestamp to be set
        */
        void set_timestamp(std::string timestamp){
            this->timestamp = timestamp;
        }

        /**
         * @brief Setter of source MAC address
         * @param src_mac MAC address to be set
        */
        void set_src_mac(std::string src_mac){
            this->src_mac = src_mac;
        }

        /**
         * @brief Setter of destination MAC address
         * @param dst_mac MAC address to be set
        */
        void set_dst_mac(std::string dst_mac){
            this->dst_mac = dst_mac;
        }

        /**
         * @brief Setter of length of packet
         * @param frame_len length to be set
        */
        void set_frame_len(int frame_len){
            this->frame_len = frame_len;
        }
        
        /**
         * @brief Setter of source IP address
         * @param src_ip IP address to be set
        */
        void set_src_ip(std::string src_ip){
            this->src_ip = src_ip;
        
        }

        /**
         * @brief Setter of destination IP address
         * @param dst_ip IP address to be set
        */
        void set_dst_ip(std::string dst_ip){
            this->dst_ip = dst_ip;
        }

        /**
         * @brief Setter of source port
         * @param src_port port to be set
        */
        void set_src_port(u_int16_t src_port){
            this->src_port = src_port;
        }

        /**
         * @brief Setter of destination port
         * @param dst_port port to be set
        */
        void set_dst_port(u_int16_t dst_port){
            this->dst_port = dst_port;
        }

        /**
         * @brief Setter of byte payload
         * @param byte_offset payload to be set
        */
        void set_byte_offset(std::string byte_offset){
            this->byte_offset = byte_offset;    
        }

        /**
         * @brief Setter of type
         * @param type type to be set
        */
        void set_type(std::string type){
            this->type = type;
        }

        /**
         * @brief Transforms the MAC address to desired format
         * 
         * @param mac MAC address to be transformed
        */
        static std::string format_mac(std::string mac);
    
        /**
         * @brief Prints the whole packet information
         * 
         * @param packet packet to be printed
        */
        void print_packet(Packet packet);

};

#endif
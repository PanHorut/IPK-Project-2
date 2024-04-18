#ifndef PACKET_HPP
#define PACKET_HPP

#include <string>
#include <string.h>
#include <netinet/in.h>



class Packet{
    private:
        std::string timestamp = "";
        int frame_len = 0;
        std::string src_ip;
        std::string dst_ip;
        //u_int16_t src_port;
        //u_int16_t dst_port;
        std::string byte_offset = "";

    public:

        u_int16_t src_port;
        u_int16_t dst_port;
        std::string src_mac;
        std::string dst_mac;

        Packet();

        void set_timestamp(std::string timestamp){
            this->timestamp = timestamp;
        }

        void set_src_mac(std::string src_mac){
            this->src_mac = src_mac;
        }

        void set_dst_mac(std::string dst_mac){
            this->dst_mac = dst_mac;
        }

        void set_frame_len(int frame_len){
            this->frame_len = frame_len;
        }
        
        void set_src_ip(std::string src_ip){
            this->src_ip = src_ip;
        
        }

        void set_dst_ip(std::string dst_ip){
            this->dst_ip = dst_ip;
        }

        void set_src_port(u_int16_t src_port){
            this->src_port = src_port;
        }

        void set_dst_port(u_int16_t dst_port){
            this->dst_port = dst_port;
        }

        void set_byte_offset(std::string byte_offset){
            this->byte_offset = byte_offset;    
        }

        static std::string format_mac(std::string mac);
    
        void print_packet(Packet packet);

};

#endif
#include "tools.hpp"
#include "packet.hpp"

ArgParser::ArgParser(int argc, char *argv[]){
    this->argc = argc;
    this->argv = argv;
}

void ArgParser::parse_arguments(){

    if (this->argc <= 1){
        std::cout << "No arguments provided." << std::endl;
        return;
    }

    std::string port_filter;
    // Loop through each argument
    for (int i = 1; i < this->argc; i++){
        char* arg = argv[i];
        char* next_arg;
        
        
        if(!strcmp(arg, "-i") || !strcmp(arg, "--interface")){
            next_arg = argv[++i];
            
            if(next_arg != NULL && next_arg[0] != '-'){
                this->interface = std::string(next_arg);

            }else{
                return;
            }
        
        }else if(!strcmp(arg, "-t") || !strcmp(arg, "--tcp")){

                if(port_filter != ""){
                    this->filter += "(tcp " + port_filter + ")";
                    port_filter = "";
                }else{
                    this->filter += "tcp";
                }
        
        }else if(!strcmp(arg, "-u") || !strcmp(arg, "--udp")){
            
                if(port_filter != ""){
                    this->filter += "(udp " + port_filter + ")";
                    port_filter = "";
                }else{
                    this->filter += "udp";
                }
        
        }else if(!strcmp(arg, "-p")){
            next_arg = argv[++i];

            if(next_arg != NULL && next_arg[0] != '-'){
                port_filter += "port " + std::string(next_arg);
            
            }else{
                std::cout << "No port provided." << std::endl;
                return;
            }

        }else if(!strcmp(arg, "--port-destination")){
            next_arg = argv[++i];

            if(next_arg != NULL && next_arg[0] != '-'){
                if(port_filter != ""){
                    port_filter += " and ";
                }
                port_filter += "dst port " + std::string(next_arg);
            
            }else{
                std::cout << "No destination port provided." << std::endl;
                return;
            }

        }else if(!strcmp(arg, "--port-source")){
            next_arg = argv[++i];

            if(next_arg != NULL && next_arg[0] != '-'){
                if(port_filter != ""){
                    port_filter += " and ";
                }
                port_filter += "src port " + std::string(next_arg);
            
            }else{
                std::cout << "No port provided." << std::endl;
                return;
            }
        }else if(!strcmp(arg, "--icmp4")){
            
            this->filter += "icmp";
        
        }else if(!strcmp(arg, "--icmp6")){
            
            this->filter += "icmp6";
        
        }else if(!strcmp(arg, "--arp")){
            
            this->filter += "arp";

        }else if(!strcmp(arg, "--ndp")){
            
            this->filter += "icmp6 and (icmp6[0] = 133 or icmp6[0] = 135 or icmp6[0] = 136)";
        
        }else if(!strcmp(arg, "--igmp")){
            
            this->filter += "igmp";
        
        }else if(!strcmp(arg, "--mld")){
            
            this->filter += "icmp6 and (icmp6[0] = 130 or icmp6[0] = 131 or icmp6[0] = 132)";

        }else if(!strcmp(arg, "-n")){
            next_arg = argv[++i];

            if(next_arg != NULL && next_arg[0] != '-' && isdigit(next_arg[0])){
                this->count = atoi(next_arg);
            
            }else{
                std::cout << "No count provided provided." << std::endl;
                return;
            }
        }else{
            std::cout << "Invalid argument: " << arg << std::endl;
            return;
        }

        if(i < this->argc-1 && strcmp(arg, "-i") && strcmp(arg, "--interface") && 
            strcmp(arg, "-p") && strcmp(arg, "--port-destination") && strcmp(arg, "--port-source") && strcmp(arg, "-n")){
            this->filter += " or ";
        }

    }
    this->filter = format_filter(this->filter);
}

std::string ArgParser::format_filter(std::string filter){

    if(filter[filter.length()-3] == 'o' && filter[filter.length()-2] == 'r' && filter[filter.length()-4] == ' '){
        filter = filter.substr(0, filter.length()-4);

    }

    return filter;

}
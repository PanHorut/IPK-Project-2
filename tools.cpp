#include "tools.hpp"

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
                port_filter += "dst port " + std::string(next_arg);
            
            }else{
                std::cout << "No destination port provided." << std::endl;
                return;
            }

        }else if(!strcmp(arg, "--port-source")){
            next_arg = argv[++i];

            if(next_arg != NULL && next_arg[0] != '-'){
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
            
            this->filter += "ndp";
        
        }else if(!strcmp(arg, "--igmp")){
            
            this->filter += "igmp";
        
        }else if(!strcmp(arg, "--mld")){
            
            this->filter += "mld";

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

        if(i < this->argc - 1 && strcmp(arg, "-i") && strcmp(arg, "--interface") && 
            strcmp(arg, "-p") && strcmp(arg, "--port-destination") && strcmp(arg, "--port-source") && strcmp(arg, "-n")){
            this->filter += " or ";
        }

    }
}
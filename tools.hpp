#ifndef TOOLS_HPP
#define TOOLS_HPP

#include <iostream>
#include <string>
#include <string.h>

class ArgParser {
    public:
    
    ArgParser(int argc, char* argv[]);

    void parse_arguments();

    std::string get_filter(){
        return this->filter;
    }

    std::string get_interface(){
        return this->interface;
    }

    int get_count(){
        return this->count;
    }
        
    private:
        int argc;
        int count = 1;
        char** argv;
        std::string filter = "";
        std::string interface;
};

#endif
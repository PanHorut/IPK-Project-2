#ifndef TOOLS_HPP
#define TOOLS_HPP

/**
 * @file   tools.hpp
 * @brief  Header file for argument parsing
 * @author Dominik Horut (xhorut01)
 */

#include <iostream>
#include <string>
#include <string.h>

#include "exception.hpp"

/**
 * @class ArgParser
 * @brief Class for parsing command line arguments.
 */
class ArgParser {
    public:
    
    /**
     * @brief Constructor for ArgParser class.
     * @param argc The number of command line arguments.
     * @param argv The array of command line arguments.
     */
    ArgParser(int argc, char* argv[]);

    /**
     * @brief Parses the command line arguments.
     */
    void parse_arguments();

    /**
     * @brief Gets the filter string.
     * @return The filter string.
     */
    std::string get_filter(){
        return this->filter;
    }

    /**
     * @brief Gets the interface string.
     * @return The interface string.
     */
    std::string get_interface(){
        return this->interface;
    }

    /**
     * @brief Gets the count value.
     * @return The count value.
     */
    int get_count(){
        return this->count;
    }

    
    
        
    private:
        int argc; 
        int count = 1;
        char** argv;
        std::string filter = ""; 
        std::string interface;

    /**
     * @brief Formats the filter string to be accepted by pcap_compile.
     * @param filter The filter string to be formatted.
     * @return The formatted filter string.
     */
    std::string format_filter(std::string filter);
};

#endif

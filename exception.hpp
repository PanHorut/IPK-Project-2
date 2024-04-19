#ifndef EXCEPTION_HPP
#define EXCEPTION_HPP

/**
 * @file   exception.hpp
 * @brief  Header file for using exception 
 * @author Dominik Horut (xhorut01)
 */

#include <iostream>
#include <exception>

/**
 * @brief Custom exception class for the sniffer.
 * 
 * This class is derived from std::exception and provides a custom exception for the sniffer.
 * It allows to specify the cause of exception
 */
class SnifferException : public std::exception {
public:

    /**
     * @brief Constructs a SnifferException object with the given message.
     * 
     * @param message The exception message.
     */
    SnifferException(const char* message) : m_message(message) {}

    /**
     * @brief Returns the exception message.
     * 
     * @return The exception message.
     */
    const char* what() const noexcept override {
        return m_message;
    }

private:
    const char* m_message;
};

#endif
#pragma once

#include <exception>
#include <string>

#include "status_code.hpp"

namespace wscpp {
namespace http {
    class exception : public std::exception {
    public:
        exception(status_code status_code, const std::string& msg)
            : _status_code(status_code)
            , _msg(msg)
        {};

        ~exception() throw() {}

        virtual const char* what() const throw() {
            return _msg.c_str();
        }

        status_code _status_code;
        std::string _msg;
    };
};
};
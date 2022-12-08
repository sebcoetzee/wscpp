#pragma once

#include <string>

namespace wscpp {
namespace http {
struct header {
    header(std::string&& name, std::string&& value) : name(name), value(value) {};

    std::string name;
    std::string value;
};
};
};
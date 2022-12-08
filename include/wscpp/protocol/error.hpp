#pragma once

#include <string>
#include <system_error>
#include <type_traits>

namespace wscpp {
namespace protocol {

enum class error_code {
    failed_handshake = 1,
    failed_frame
};

class protocol_category : public std::error_category {
public:
    const char* name() const noexcept override {
        return "websockets.protocol";
    }

    std::string message(int value) const override {
        switch (value)
        {
        case static_cast<int>(error_code::failed_handshake):
            return "Failed Handshake";
        case static_cast<int>(error_code::failed_frame):
            return "Failed Frame";
        default:
            return "Unknown Error";
        }
    }
};

const protocol_category& get_protocol_category() {
    static protocol_category instance{};
    return instance;
};

};
};

namespace std
{
    template <>
    struct is_error_code_enum<wscpp::protocol::error_code> : true_type {};

    std::error_code make_error_code(wscpp::protocol::error_code ec) {
        return std::error_code(static_cast<int>(ec), wscpp::protocol::get_protocol_category());
    }
}
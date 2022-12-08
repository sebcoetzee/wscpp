#pragma once

#include <sstream>
#include <string>
#include <vector>

#include "asio.hpp"
#include "constants.hpp"
#include "header.hpp"
#include "status_code.hpp"

namespace wscpp {
namespace http {
struct response {
public:
    response(status_code code, std::vector<header>&& headers, std::string&& content) :
        _code(std::move(code)),
        _headers(std::move(headers)),
        _content(std::move(content)),
        _status_line(std::move(status_line())) {
        };

    std::vector<asio::const_buffer> to_buffers() {
        std::vector<asio::const_buffer> buffers;
        buffers.push_back(asio::buffer(_status_line));
        buffers.push_back(asio::buffer(CRLF));
        for (std::size_t i = 0; i < _headers.size(); i++) {
            buffers.push_back(asio::buffer(_headers[i].name));
            buffers.push_back(asio::buffer(HEADER_SEPARATOR));
            buffers.push_back(asio::buffer(_headers[i].value));
            buffers.push_back(asio::buffer(CRLF));
        }
        buffers.push_back(asio::buffer(CRLF));
        buffers.push_back(asio::buffer(_content));
        return std::move(buffers);
    };

    std::string status_line() const {
        std::stringstream line;
        line << "HTTP/" << _http_version << " " << std::to_string(static_cast<int>(_code)) << " " << reason_phrase(_code);
        return line.str();
    };

    std::string _http_version = "1.1";
    status_code _code;
    std::string _status_line;
    std::vector<header> _headers;
    std::string _content;
};
};
};
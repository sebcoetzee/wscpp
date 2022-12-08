#pragma once

namespace wscpp {
namespace http {
enum class status_code {
continue_code = 100,
switching_protocols = 101,

ok = 200,
created = 201,
accepted = 202,
non_authoritative_information = 203,
no_content = 204,
reset_content = 205,
partial_content = 206,

multiple_choices = 300,
moved_permanently = 301,
found = 302,
see_other = 303,
not_modified = 304,
use_proxy = 305,
temporary_redirect = 307,

bad_request = 400,
unauthorized = 401,
payment_required = 402,
forbidden = 403,
not_found = 404,
method_not_allowed = 405,
not_acceptable = 406,
proxy_authentication_required = 407,
request_timeout = 408,
conflict = 409,
gone = 410,
length_required = 411,
precondition_failed = 412,
request_entity_too_large = 413,
request_uri_too_long = 414,
unsupported_media_type = 415,
request_range_not_satisfiable = 416,
expectation_failed = 417,
im_a_teapot = 418,
upgrade_required = 426,
precondition_required = 428,
too_many_requests = 429,
request_header_fields_too_large = 431,

internal_server_error = 500,
not_implemented = 501,
bad_gateway = 502,
service_unavailable = 503,
gateway_timeout = 504,
http_version_not_supported = 505,
not_extended = 510,
network_authentication_required = 511
};

std::string reason_phrase(status_code code) {
    switch (code) {
        case status_code::continue_code:
            return "Continue";
        case status_code::switching_protocols:
            return "Switching Protocols";
        case status_code::ok:
            return "OK";
        case status_code::created:
            return "Created";
        case status_code::accepted:
            return "Accepted";
        case status_code::non_authoritative_information:
            return "Non Authoritative Information";
        case status_code::no_content:
            return "No Content";
        case status_code::reset_content:
            return "Reset Content";
        case status_code::partial_content:
            return "Partial Content";
        case status_code::multiple_choices:
            return "Multiple Choices";
        case status_code::moved_permanently:
            return "Moved Permanently";
        case status_code::found:
            return "Found";
        case status_code::see_other:
            return "See Other";
        case status_code::not_modified:
            return "Not Modified";
        case status_code::use_proxy:
            return "Use Proxy";
        case status_code::temporary_redirect:
            return "Temporary Redirect";
        case status_code::bad_request:
            return "Bad Request";
        case status_code::unauthorized:
            return "Unauthorized";
        case status_code::payment_required:
            return "Payment Required";
        case status_code::forbidden:
            return "Forbidden";
        case status_code::not_found:
            return "Not Found";
        case status_code::method_not_allowed:
            return "Method Not Allowed";
        case status_code::not_acceptable:
            return "Not Acceptable";
        case status_code::proxy_authentication_required:
            return "Proxy Authentication Required";
        case status_code::request_timeout:
            return "Request Timeout";
        case status_code::conflict:
            return "Conflict";
        case status_code::gone:
            return "Gone";
        case status_code::length_required:
            return "Length Required";
        case status_code::precondition_failed:
            return "Precondition Failed";
        case status_code::request_entity_too_large:
            return "Request Entity Too Large";
        case status_code::request_uri_too_long:
            return "Request-URI Too Long";
        case status_code::unsupported_media_type:
            return "Unsupported Media Type";
        case status_code::request_range_not_satisfiable:
            return "Requested Range Not Satisfiable";
        case status_code::expectation_failed:
            return "Expectation Failed";
        case status_code::im_a_teapot:
            return "I'm a teapot";
        case status_code::upgrade_required:
            return "Upgrade Required";
        case status_code::precondition_required:
            return "Precondition Required";
        case status_code::too_many_requests:
            return "Too Many Requests";
        case status_code::request_header_fields_too_large:
            return "Request Header Fields Too Large";
        case status_code::internal_server_error:
            return "Internal Server Error";
        case status_code::not_implemented:
            return "Not Implemented";
        case status_code::bad_gateway:
            return "Bad Gateway";
        case status_code::service_unavailable:
            return "Service Unavailable";
        case status_code::gateway_timeout:
            return "Gateway Timeout";
        case status_code::http_version_not_supported:
            return "HTTP Version Not Supported";
        case status_code::not_extended:
            return "Not Extended";
        case status_code::network_authentication_required:
            return "Network Authentication Required";
        default:
            return "Unknown";
    }
};
};
};
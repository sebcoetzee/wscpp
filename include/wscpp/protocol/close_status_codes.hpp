# pragma once

namespace wscpp {
namespace protocol {

enum close_status_code : short unsigned int {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    reserved = 1004,
    reserved_no_status_code = 1005,
    reserved_abnormal_close = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    extension_required = 1010,
    internal_endpoint_error = 1011,
    service_restart = 1012,
    try_again_later = 1013,
    bad_gateway = 1014,
    tls_handshake = 1015
};

};
};
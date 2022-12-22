#pragma once

#include <cstddef>
#include <system_error>
#include <memory>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#ifndef ASIO_HPP
#include "asio.hpp"
#endif
#include "close_status_codes.hpp"
#include "converters.hpp"
#include "header.hpp"
#include "payload.hpp"

namespace wscpp {
namespace protocol {

enum class frame_state {
    basic_header,
    extended_payload_length,
    masking_key,
    payload
};

class frame {
public:
    frame() : _state(frame_state::basic_header), _basic_header(basic_header()), _terminate(false) {};
    frame(std::vector<uint8_t> payload, const std::size_t payload_length, const enums::opcode opcode, bool fin):
        _state(frame_state::payload),
        _basic_header(fin, false, false, false, opcode, false, payload_length > 65535 ? 127 : payload_length > 125 ? 126 : payload_length),
        _payload(std::move(payload)),
        _terminate(false)
    {
        if (payload_length > 125) {
            _extended_payload_length.emplace(payload_length);
        }
    };

    size_t consume(const uint8_t* buffer, const std::size_t bytes_to_read, std::error_code& ec) {
        std::size_t _ptr = 0;
        while (_ptr < bytes_to_read) {
            if (_state == frame_state::basic_header) {
                _ptr += _basic_header.consume(buffer + _ptr, bytes_to_read - _ptr);
                if (_basic_header.completed()) {
                    _payload_length = _basic_header.payload_length();
                    std::cout << "Payload length: " << std::to_string(_payload_length) << std::endl;
                    if (_payload_length > 125) {
                        _state = frame_state::extended_payload_length;
                        _extended_payload_length.emplace(_payload_length);
                    } else if (_basic_header.mask()) {
                        _state = frame_state::masking_key;
                        _masking_key.emplace(masking_key());
                    } else {
                        _state = frame_state::payload;
                    }
                }
            } else if (_state == frame_state::extended_payload_length) {
                _ptr += _extended_payload_length->consume(buffer + _ptr, bytes_to_read - _ptr);
                if (_extended_payload_length->completed()) {
                    _payload_length = _extended_payload_length->payload_length();
                    if (_basic_header.mask()) {
                        _state = frame_state::masking_key;
                        _masking_key.emplace(masking_key());
                    } else {
                        _state = frame_state::payload;
                        _payload.emplace(_payload_length);
                    }
                }
            } else if (_state == frame_state::masking_key) {
                _ptr += _masking_key->consume(buffer + _ptr, bytes_to_read - _ptr);
                if (_masking_key->completed()) {
                    _state = frame_state::payload;
                    _payload.emplace(_payload_length, true, _masking_key->key());
                }
            } else if (_state == frame_state::payload) {
                _ptr += _payload->consume(buffer + _ptr, bytes_to_read - _ptr);
                if(_payload->completed()) {
                    std::cout << "Payload: ";
                    for (std::size_t i = 0; i < _payload_length; i++) {
                        std::cout << _payload->data()[i];
                    }
                    std::cout << std::endl;

                    return _ptr;
                }
            }
        }

        return _ptr;
    };

    bool final() const {
        return _basic_header.fin();
    };

    bool completed() const {
        return _state == frame_state::payload && _payload->completed();
    };

    protocol::enums::opcode opcode() const {
        return _basic_header.opcode();
    };

    std::vector<uint8_t>& data() {
        return _payload->data();
    };

    std::vector<asio::const_buffer> to_buffers() const {
        std::vector<asio::const_buffer> buffers;
        auto header_buffers = _basic_header.to_buffer();
        for (std::size_t i = 0; i < header_buffers.size(); i++) {
            buffers.push_back(header_buffers[i]);
        };

        if (_extended_payload_length) {
            buffers.push_back(_extended_payload_length->to_buffer());
        }

        if (_masking_key) {
            buffers.push_back(_masking_key->to_buffer());
        }

        if (_payload) {
            buffers.push_back(_payload->to_buffer());
        }

        return buffers;
    };

    std::string to_string() const {
        std::stringstream stream;
        stream << "Opcode: " << enums::opcode_string(opcode()) << std::endl;
        return stream.str();
    };

    bool get_terminate() const {
        return _terminate;
    };

    void set_terminate(bool terminate) {
        _terminate = terminate;
    };

private:
    frame_state _state;
    basic_header _basic_header;
    std::optional<extended_payload_length> _extended_payload_length = std::nullopt;
    std::size_t _payload_length;
    std::optional<masking_key> _masking_key = std::nullopt;
    std::optional<payload> _payload = std::nullopt;
    bool _terminate;
};

auto make_close_frame(short unsigned int close_status_code) {
    uint16_t_to_uint8_t converter;
    converter.u16 = close_status_code;
    uint8_t payload[2] = {converter.u8[1], converter.u8[0]};

    return frame(std::move(std::vector(payload, payload + 2)), 2, enums::opcode::close, true);
};

};
};
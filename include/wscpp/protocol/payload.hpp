#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace wscpp {
namespace protocol {

class payload {
public:
    payload(std::size_t payload_length, bool is_masked = false, uint32_t masking_key = 0) : _payload_length(payload_length), _is_masked(is_masked), _ptr(0), _data(payload_length) {
        for (int i = 3; i >=0; i--) {
            _masking_key[i] = static_cast<uint8_t>(masking_key);
            masking_key = masking_key >> 8;
        }
    };

    payload(std::vector<uint8_t> data) : _payload_length(data.size()), _is_masked(false), _data(std::move(data)) {}

    std::size_t consume(const uint8_t* buffer, std::size_t bytes_available) {
        std::size_t bytes_consumed(0);
        if (_is_masked) {
            while (bytes_available > 0 && _ptr < _payload_length) {
                *(_data.data() + _ptr) = *(buffer + _ptr) ^ _masking_key[_ptr % 4];
                _ptr++;
                bytes_available--;
                bytes_consumed++;
            }
        } else {
            while (bytes_available > 0 && _ptr < _payload_length) {
                *(_data.data() + _ptr) = *(buffer + _ptr);
                _ptr++;
                bytes_available--;
                bytes_consumed++;
            }
        }

        return bytes_consumed;
    };

    std::vector<uint8_t>& data() {
        return _data;
    };

    bool completed() const {
        return _ptr == _payload_length;
    }

    asio::const_buffer to_buffer() const {
        return asio::const_buffer(_data.data(), _payload_length);
    }

private:
    std::size_t _payload_length;
    bool _is_masked;
    uint8_t _masking_key[4];
    std::size_t _ptr;
    std::vector<uint8_t> _data;
};

};
};
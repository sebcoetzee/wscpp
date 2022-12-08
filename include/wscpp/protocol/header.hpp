#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <limits>

#include "asio.hpp"

namespace wscpp {
namespace protocol {

// bit masks
static constexpr uint8_t MASK_FIN = 0x80;
static constexpr uint8_t MASK_RSV1 = 0x40;
static constexpr uint8_t MASK_RSV2 = 0x20;
static constexpr uint8_t MASK_RSV3 = 0x10;
static constexpr uint8_t MASK_OPCODE = 0x0F;

static constexpr uint8_t MASK_MASK = 0x80;
static constexpr uint8_t MASK_PAYLOAD = 0x7F;

namespace enums {
enum struct opcode : uint8_t {
    continuation = 0x00,
    text = 0x01,
    binary = 0x02,
    rsv3 = 0x03,
    rsv4 = 0x04,
    rsv5 = 0x05,
    rsv6 = 0x06,
    rsv7 = 0x07,
    close = 0x08,
    ping = 0x09,
    pong = 0x0A,
    control_rsvb = 0x0B,
    control_rsvc = 0x0C,
    control_rsvd = 0x0D,
    control_rsve = 0x0E,
    control_rsvf = 0x0F
};

std::string opcode_string(opcode code) {
    switch (code)
    {
    case opcode::continuation:
        return "Continuation";
        break;
    case opcode::text:
        return "Text";
        break;
    case opcode::binary:
        return "Binary";
        break;
    case opcode::close:
        return "Close";
        break;
    case opcode::ping:
        return "Ping";
        break;
    case opcode::pong:
        return "Pong";
        break;
    
    default:
        return "Unknown";
        break;
    }
};
}

struct basic_header {
    basic_header() : _b0(0x00), _b1(0x00), _bytes_needed(2) {};
    basic_header(bool fin, bool rsv1, bool rsv2, bool rsv3, enums::opcode opcode, bool mask, uint8_t payload_length): _b0(static_cast<uint8_t>(opcode)), _b1(payload_length), _bytes_needed(0) {
        if (fin) {
            _b0 |= MASK_FIN;
        }

        if (rsv1) {
            _b0 |= MASK_RSV1;
        }

        if (rsv2) {
            _b0 |= MASK_RSV2;
        }

        if (rsv3) {
            _b0 |= MASK_RSV3;
        }
    }

    std::size_t consume(uint8_t const * buffer, std::size_t bytes_available) {
        std::size_t bytes_consumed = 0;
        while (_bytes_needed > 0 && bytes_available > 0) {
            if (_bytes_needed == 2) {
                _b0 = *buffer;
                bytes_consumed++;
                buffer++;
                _bytes_needed--;
                bytes_available--;
            } else {
                _b1 = *buffer;
                bytes_consumed++;
                buffer++;
                _bytes_needed--;
                bytes_available--;
            }
        }
        return bytes_consumed;
    }

    bool fin() const {
        return (_b0 & MASK_FIN) == MASK_FIN;
    }

    bool rsv1() const {
        return (_b0 & MASK_RSV1) == MASK_RSV1;
    }

    bool rsv2() const {
        return (_b0 & MASK_RSV2) == MASK_RSV2;
    }

    bool rsv3() const {
        return (_b0 & MASK_RSV3) == MASK_RSV3;
    }

    enums::opcode opcode() const {
        return static_cast<enums::opcode>(_b0 & MASK_OPCODE);
    }

    bool mask() const {
        return (_b1 & MASK_MASK) == MASK_MASK;
    }

    uint8_t payload_length() const {
        return _b1 & MASK_PAYLOAD;
    }

    bool completed() const {
        return _bytes_needed == 0;
    }

    std::vector<asio::const_buffer> to_buffer() const {
        return {asio::const_buffer(&_b0, 1), asio::const_buffer(&_b1, 1)};
    }

    uint8_t _b0;
    uint8_t _b1;
    size_t _bytes_needed;
};

struct extended_payload_length {
    extended_payload_length(uint8_t initial_length) {
        if (initial_length == 126) {
            _bytes_needed = 4;
            _buff_size = 4;
        } else if (initial_length == 127) {
            _bytes_needed = 8;
            _buff_size = 8;
        } else {
            throw std::invalid_argument("Extended payload only applies when initial payload length is > 125");
        }
    };

    extended_payload_length(uint64_t payload_length) : _payload_length(payload_length) {};

    void set_initial_length(uint8_t initial_length) {
        if (initial_length == 126) {
            _bytes_needed = 4;
            _buff_size = 4;
        } else if (initial_length == 127) {
            _bytes_needed = 8;
            _buff_size = 8;
        } else {
            throw std::invalid_argument("Extended payload only applies when initial payload length is > 125");
        }
    }

    std::size_t consume(uint8_t const * buffer, std::size_t bytes_available) {
        std::size_t bytes_consumed = 0;
        while (_bytes_needed > 0 && bytes_available > 0) {
            _buff[8 - _bytes_needed] = *buffer;
            _bytes_needed--;
            bytes_available--;
            bytes_consumed++;
        }
        if (completed()) {
            for (std::size_t i = _buff_size; i > 0; i--) {
                _payload_length = _payload_length | (static_cast<uint64_t>(_buff[_buff_size - i]) << (8 * (i - 1)));
            }
        }
        return bytes_consumed;
    }

    // TODO: Does this conversion make sense on 32-bit systems?
    std::size_t payload_length() {
        return _payload_length;
    }

    bool completed() {
        return _bytes_needed == 0;
    }

    asio::const_buffer to_buffer() const {
        if (_payload_length <= std::numeric_limits<uint16_t>::max()) {
            return asio::const_buffer(&_payload_length + 6, 2);
        } else {
            return asio::const_buffer(&_payload_length, 8);
        }
    }

    uint8_t _buff[8];
    std::size_t _buff_size;
    uint64_t _payload_length;
    std::size_t _bytes_needed;
};

struct masking_key {
    masking_key() : _bytes_needed(4), _masking_key(0) {};

    masking_key(uint32_t key) : _masking_key(key) {};

    std::size_t consume(uint8_t const * buffer, std::size_t bytes_available) {
        std::size_t bytes_consumed = 0;
        while (_bytes_needed > 0 && bytes_available > 0) {
            _buff[4 - _bytes_needed] = *(buffer + bytes_consumed);
            _bytes_needed--;
            bytes_available--;
            bytes_consumed++;
        }
        if (completed()) {
            for (std::size_t i = 4; i > 0; i--) {
                _masking_key = _masking_key | (static_cast<uint64_t>(_buff[4 - i]) << (8 * (i - 1)));
            }
        }
        return bytes_consumed;
    }

    uint32_t key() {
        return _masking_key;
    }

    bool completed() {
        return _bytes_needed == 0;
    }

    asio::const_buffer to_buffer() const {
        return asio::const_buffer(&_masking_key, 4);
    }

    uint8_t _buff[4];
    uint32_t _masking_key;
    std::size_t _bytes_needed;
};

};
};
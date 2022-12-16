#include <cstdint>

namespace wscpp {
namespace protocol {

union uint16_t_to_uint8_t {
    uint16_t u16;
    uint8_t  u8[2];
};

};
};
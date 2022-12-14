#include <functional>
#include <iostream>
#include <memory>
// #include <utility>
// #include <type_traits>
#include <chrono>
#include <mutex>
#include <deque>
#include <random>
#include <array>
#include <cstdlib>

#include "sha1.h"
#include "cppcodec/base64_default_rfc4648.hpp"
#include "httpparser/request.h"
#include "httpparser/httprequestparser.h"
#include "http/header.hpp"
#include "http/response.hpp"
#include "http/status_code.hpp"
#include "asio.hpp"
#include "protocol/frame.hpp"
#include "uuid.h"

using asio::ip::tcp;

using namespace httpparser;
using namespace uuids;

using std::placeholders::_1;
using std::placeholders::_2;

constexpr size_t buffer_size = 16384;
constexpr size_t max_frame_size = 16376;

namespace wscpp {

using protocol::enums::opcode;

struct params {
    asio::io_context& io_context;
    tcp::socket socket;
    uint handshake_timeout = 5;
    uint keepalive_interval = 20;
    uint keepalive_timeout = 10;
};

class websocket_connection {
public:
    websocket_connection(params p);
    tcp::socket& socket();

    void set_binary_message_handler(std::function<void (std::vector<uint8_t>)> handler);
    void set_close_handler(std::function<void ()> handler);
    void set_text_message_handler(std::function<void (std::string)> handler);
    void start();

    /**
     * @brief Write a text frame to the websocket connection. This frame is
     * pushed to the back of the queue of pending frames. This method acquires
     * the connection's write lock.
     *
     * @param payload String message body.
     */
    void write(const std::string payload);

    /**
     * @brief Write a binary frame to the websocket connection. This frame is
     * pushed to the back of the queue of pending frames. This method acquires
     * the connection's write lock.
     * 
     * @param payload Raw pointer to data array that will be copied into the frame.
     * @param length Length of the data to be copied.
     */
    void write(const void* payload, std::size_t length);

    uuids::uuid _id;
    // void write(const void* payload, size_t len);
private:
    void close_connection(const std::string message);
    protocol::frame& current_frame();
    void frame_handler(const asio::error_code& ec, std::size_t bytes_transferred);
    void handshake_handler(const asio::error_code& ec, std::size_t bytes_transferred);
    void handshake_timeout_handler(const asio::error_code& ec);
    void keepalive_handler(const asio::error_code& ec);
    void send_pong(std::vector<uint8_t> payload);
    void start_keepalive();
    void start_reading();
    void queue_write_frame(protocol::frame frame);
    void write_pending_frames();

    std::vector<uint8_t> _buffer;
    tcp::socket _socket;
    asio::io_context& _io_context;
    std::function<void (std::vector<uint8_t>)> _binary_handler;
    std::function<void (std::optional<int> status_code, std::string reason)> _close_handler;
    std::function<void (std::string)> _text_handler;

    // timers and timeouts
    asio::steady_timer _handshake_timer;
    asio::steady_timer _keepalive_timer;
    asio::steady_timer _keepalive_timeout_timer;
    uint _handshake_timeout;
    uint _keepalive_interval;
    uint _keepalive_timeout;


    std::vector<protocol::frame> _frames;
    std::mutex _read_mutex;
    std::mutex _write_mutex;

    // Ping payload of the last ping that was sent on this connection
    std::vector<uint8_t> _ping_payload;

    bool _write_in_progress;
    std::deque<protocol::frame> _write_frames;
    std::optional<const protocol::frame> _write_hold_frame;
    std::optional<protocol::enums::opcode> _current_opcode;
    bool _close_sent;
};

void websocket_connection::set_binary_message_handler(std::function<void (std::vector<uint8_t>)> handler) {
    _binary_handler = handler;
};

void websocket_connection::set_text_message_handler(std::function<void (std::string)> handler) {
    _text_handler = handler;
};

void websocket_connection::start()
{
    _handshake_timer.expires_after(std::chrono::seconds(_handshake_timeout));
    _handshake_timer.async_wait(std::bind(&websocket_connection::handshake_timeout_handler, this, _1));
    _socket.async_read_some(asio::buffer(_buffer, buffer_size), std::bind(&websocket_connection::handshake_handler, this, _1, _2));
};

void websocket_connection::start_keepalive()
{
    _keepalive_timer.expires_after(std::chrono::seconds(_keepalive_interval));
    _keepalive_timer.async_wait(std::bind(&websocket_connection::keepalive_handler, this, _1));
};

void websocket_connection::start_reading()
{
    _socket.async_read_some(asio::buffer(_buffer, buffer_size), std::bind(&websocket_connection::frame_handler, this, _1, _2));
};

tcp::socket& websocket_connection::socket()
{
    return _socket;
};

inline uuid generate_uuid() {
    std::random_device rd;
    auto seed_data = std::array<int, std::mt19937::state_size> {};
    std::generate(std::begin(seed_data), std::end(seed_data), std::ref(rd));
    std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
    std::mt19937 generator(seq);
    uuids::uuid_random_generator gen{generator};
    return gen();
};

websocket_connection::websocket_connection(params p) :
    _current_opcode(std::nullopt),
    _socket(std::move(p.socket)),
    _buffer(buffer_size),
    _binary_handler([](auto) {}),
    _close_handler([](auto, auto) {}),
    _text_handler([](auto) {}),
    _write_in_progress(false),
    _close_sent(false),
    _id(generate_uuid()),
    _io_context(p.io_context),
    _handshake_timer(p.io_context),
    _keepalive_timer(p.io_context),
    _keepalive_timeout_timer(p.io_context),
    _handshake_timeout(p.handshake_timeout),
    _keepalive_interval(p.keepalive_interval),
    _keepalive_timeout(p.keepalive_timeout)
{};

void websocket_connection::handshake_timeout_handler(const asio::error_code& ec)
{
    if (!ec) {
        close_connection("Handshake timed out!");
    }
};

inline std::vector<uint8_t> generate_ping_body() {
    std::vector<uint8_t> ping_body;
    for (std::size_t i = 0; i < 4; i++)
    {
        ping_body.emplace_back(rand() % 0xff);
    }
    return ping_body;
};

void websocket_connection::keepalive_handler(const asio::error_code& ec) {
    if (!ec) {
        _ping_payload = generate_ping_body();
        protocol::frame frame(_ping_payload, _ping_payload.size(), protocol::enums::opcode::ping, true);
        std::lock_guard lock(_write_mutex);
        _write_frames.push_front(std::move(frame));
        write_pending_frames();
        start_keepalive();
    }
}

const std::string EMPTY_STRING = "";

inline const std::string& sec_websocket_key(const std::vector<httpparser::Request::HeaderItem>& headers) {
    for (std::size_t i = 0; i < headers.size(); i++) {
        if (headers[i].name == "Sec-WebSocket-Key") {
            return headers[i].value;
        }
    }
    return EMPTY_STRING;
};

inline auto create_sec_websocket_accept(const std::string& sec_websocket_key) {
    std::string raw_sec_websocket_accept = sec_websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::vector<unsigned char> hash(20);
    sha1::calc(raw_sec_websocket_accept.data(), raw_sec_websocket_accept.size(), hash.data());
    return base64::encode(hash.data(), 20);
};

void websocket_connection::handshake_handler(const asio::error_code& ec, std::size_t bytes_transferred)
{
    _handshake_timer.cancel();
    if (!ec) {
        Request request;
        HttpRequestParser parser;

        HttpRequestParser::ParseResult res = parser.parse(request, reinterpret_cast<const char *>(_buffer.data()), reinterpret_cast<const char *>(_buffer.data()) + bytes_transferred);
        if (res == HttpRequestParser::ParseResult::ParsingCompleted)
        {
            std::cout << request.inspect() << std::endl;
            if (request.method == "GET") {
                auto& key = sec_websocket_key(request.headers);
                if (key.empty()) {
                    close_connection("Handshake: No Sec-Websocket-Key sent in the handshake request");
                    return;
                }

                auto sec_websocket_accept = create_sec_websocket_accept(key);

                std::cout << "Sec-Websocket-Accept: " << sec_websocket_accept << std::endl;

                std::vector<http::header> headers;
                headers.push_back(http::header("Upgrade", "websocket"));
                headers.push_back(http::header("Connection", "Upgrade"));
                headers.push_back(http::header("Sec-Websocket-Accept", std::move(sec_websocket_accept)));
                http::response response(http::status_code::switching_protocols, std::move(headers), "");
                asio::async_write(_socket, response.to_buffers(), [this](const std::error_code& ec, std::size_t){
                    start_reading();
                    start_keepalive();
                    if (!ec) {
                        std::cout << "Message successfully sent" << std::endl;
                    } else {
                        std::cout << "Error: " << ec << std::endl;
                    }
                });
            } else {
                std::cout << "Invalid request method: " << request.method << std::endl;
                close_connection("Handshake: Only the GET method is supported");
            }
        } else {
            close_connection("Parsing Error: Closing the connection");
        }
        // asio::async_read(_socket, asio::buffer(_buffer), std::bind(&websocket_connection::handshake_handler, shared_from_this(), _1, _2));
    } else {
        close_connection(ec.message());
    }
};

protocol::frame& websocket_connection::current_frame() {
    if (_frames.size() == 0 || _frames.back().completed()) {
        _frames.push_back(protocol::frame());
    }

    return _frames.back();
};

inline std::optional<int> parse_close_status_code(protocol::frame& frame) {
    auto& payload = frame.data();
    if (payload.size() >= 2) {
        int status_code = 0;
        status_code |= payload[0] << 8;
        status_code |= payload[1];
        return std::make_optional(status_code);
    } else {
        return std::nullopt;
    }
};

inline std::string parse_close_status_reason(protocol::frame& frame) {
    auto& payload = frame.data();
    if (payload.size() >= 2) {
        std::string reason(payload.begin() + 2, payload.end());
        return reason;
    } else {
        return "";
    }
};


void websocket_connection::frame_handler(const asio::error_code& ec, std::size_t bytes_transferred)
{
    if (!ec) {
        std::lock_guard lock(_read_mutex);

        std::error_code frame_error;

        std::size_t bytes_consumed = 0;
        while (bytes_consumed < bytes_transferred) {
            auto& frame = current_frame();
            bytes_consumed += frame.consume(_buffer.data() + bytes_consumed, bytes_transferred, frame_error);
            if (frame.completed()) {
                std::cout << "Frame received" << std::endl;
                std::cout << frame.to_string() << std::endl;
                switch (frame.opcode())
                {
                case opcode::binary:
                    if (_current_opcode) {
                        close_connection("New binary frame received while still processing continuation frames");
                        return;
                    } else if (frame.final()) {
                        // If the frame is final then we needn't worry about setting the _current_opcode.
                        _binary_handler(std::move(frame.data()));
                        _frames.pop_back();
                    } else {
                        _current_opcode.emplace(opcode::binary);
                    }
                    break;
                case opcode::close:
                    if (_close_sent) {
                        // If we've already sent a close frame then this is just
                        // the response to that close frame. We may close the
                        // socket connection now.
                        close_connection("Closing socket connection");
                    } else {
                        auto status_code = parse_close_status_code(frame);
                        auto status_reason = parse_close_status_reason(frame);
                        // The opposite party wants to close the connection.
                        _close_handler(status_code, status_reason);
                    }
                case opcode::continuation:
                    if (!_current_opcode.has_value()) {
                        close_connection("Continuation frame received but no current opcode being processed");
                        return;
                    } else if (frame.final()) {
                        std::size_t payload_size = 0;
                        for (size_t i = 0; i < _frames.size(); i++)
                        {
                            payload_size += _frames[i].data().size();
                        }

                        if (_current_opcode == opcode::binary) {
                            std::vector<uint8_t> full_payload(payload_size);
                            for (size_t i = 0; i < _frames.size(); i++)
                            {
                                auto& frame_data = _frames[i].data();
                                for (size_t j = 0; j < frame_data.size(); j++)
                                {
                                    full_payload.push_back(frame_data[j]);
                                }
                            }

                            _binary_handler(std::move(full_payload));
                        } else if (_current_opcode == opcode::text) {
                            std::string full_payload{};
                            for (size_t i = 0; i < _frames.size(); i++)
                            {
                                auto& frame_data = _frames[i].data();
                                for (size_t j = 0; j < frame_data.size(); j++)
                                {
                                    full_payload.push_back(frame_data[j]);
                                }
                            }

                            _text_handler(std::move(full_payload));
                        }

                        _frames.clear();
                        _current_opcode.reset();
                    } else {
                        close_connection("Continuation frame received but no current opcode being processed");
                        return;
                    }
                    break;
                case opcode::ping:
                    send_pong(std::move(frame.data()));
                    _frames.pop_back();
                    break;
                case opcode::pong:
                    // TODO: Implement a pong handler
                    break;

                case opcode::text:
                    if (_current_opcode) {
                        close_connection("New text frame received while still processing continuation frames");
                        return;
                    } else if (frame.final()) {
                        // If the frame is final then we needn't worry about setting the _current_opcode.
                        std::string payload{};
                        auto& frame_data = frame.data();
                        for (size_t j = 0; j < frame_data.size(); j++)
                        {
                            payload.push_back(frame_data[j]);
                        }
                        _text_handler(std::move(payload));
                        _frames.pop_back();
                    } else {
                        _current_opcode.emplace(opcode::binary);
                    }
                    break;
                default:
                    break;
                }
            }
        }
        start_reading();
    } else {
        close_connection(ec.message());
    }
};

/**
 * @brief Send a pong frame on the connection with the given payload.
 * 
 * @param payload uint8_t version that would typically match the payload
 * that was received in an earlier ping.
 */
void websocket_connection::send_pong(std::vector<uint8_t> payload) {
    std::size_t payload_length(payload.size());
    protocol::frame frame(std::move(payload), payload_length, protocol::enums::opcode::pong, true);
    std::lock_guard lock(_write_mutex);

    // Push the frame onto the front of the queue so that it is ahead of all
    // other frames. Pings should be responded to as soon as possible and should
    // take priority over other frames.
    _write_frames.push_front(std::move(frame));
    write_pending_frames();
};

void websocket_connection::write(const std::string message) {
    std::vector<protocol::frame> frames;
    auto first_frame(true);
    auto ptr = message.begin();
    while (ptr < message.end()) {
        auto end = std::min(ptr + max_frame_size, message.end());
        auto last_frame = end == message.end();
        std::vector<uint8_t> payload(ptr, end);
        protocol::frame frame(
            std::move(payload),
            payload.size(),
            first_frame ? protocol::enums::opcode::text : protocol::enums::opcode::continuation,
            last_frame
        );
        frames.emplace_back(
            std::move(payload),
            payload.size(),
            first_frame ? protocol::enums::opcode::text : protocol::enums::opcode::continuation,
            last_frame
        );

        ptr = end;
        first_frame = false;
    }

    std::lock_guard lock(_write_mutex);

    for (std::size_t i = 0; i < frames.size(); i++){
        _write_frames.push_back(std::move(frames[i]));
    }

    write_pending_frames();
};

void websocket_connection::write(const void* payload, std::size_t length) {
    std::vector<protocol::frame> frames;
    auto first_frame(true);
    auto ptr = static_cast<const uint8_t*>(payload);
    auto payload_end = ptr + length;
    while (ptr < payload_end) {
        auto end = std::min(ptr + max_frame_size, payload_end);
        auto last_frame = end == payload_end;
        std::vector<uint8_t> payload(ptr, end);
        frames.emplace_back(
            std::move(payload),
            payload.size(),
            first_frame ? protocol::enums::opcode::binary : protocol::enums::opcode::continuation,
            last_frame
        );

        ptr = end;
        first_frame = false;
    }

    std::lock_guard lock(_write_mutex);

    for (std::size_t i = 0; i < frames.size(); i++){
        _write_frames.push_back(std::move(frames[i]));
    }

    write_pending_frames();
};

/**
 * @brief Asynchronously write pending frames to the underlying socket.
 *
 * NB: This method should only be called from a context where the _write_mutex
 * is already held.
 *
 * If a write is already in progress, this method should return. Only one write
 * is allowed at a time.
 */
void websocket_connection::write_pending_frames() {
    if (_write_in_progress) {
        return;
    }

    if (_write_frames.size() == 0) {
        return;
    }

    _write_in_progress = true;

    _write_hold_frame.emplace(std::move(_write_frames.front()));
    _write_frames.pop_front();

    asio::async_write(_socket, std::move(_write_hold_frame->to_buffers()), [this](const asio::error_code& ec, std::size_t) {
        std::lock_guard lock(_write_mutex);
        _write_in_progress = false;

        if (!ec) {
            if (_write_frames.size() > 0) {
                write_pending_frames();
            }
        } else if (ec.value() != asio::error::operation_aborted) {
            close_connection(ec.message());
        }
    });
};

// void websocket_connection::close_connection(short unsigned int close_status_code, const std::string message) {
//     std::lock_guard lock(_write_mutex);

//     auto close_frame = protocol::make_close_frame(close_status_code);

//     if (_close_sent) {
//         return;
//     }

//     _write_frames.clear();
//     _write_frames.push_back(std::move(close_frame));

//     write_pending_frames();

//     asio::async_write(_socket,

//     auto ptr = static_cast<const uint8_t*>(payload);
//     auto payload_end = ptr + length;
//     while (ptr < payload_end) {
//         auto end = std::min(ptr + max_frame_size, payload_end);
//         auto last_frame = end == payload_end;
//         std::vector<uint8_t> payload(ptr, end);
//         frames.emplace_back(
//             std::move(payload),
//             payload.size(),
//             first_frame ? protocol::enums::opcode::binary : protocol::enums::opcode::continuation,
//             last_frame
//         );

//         ptr = end;
//         first_frame = false;
//     }

//     std::lock_guard lock(_write_mutex);

//     for (std::size_t i = 0; i < frames.size(); i++){
//         _write_frames.push_back(std::move(frames[i]));
//     }

//     write_pending_frames();

//     if (_socket.is_open()) {
//         std::cout << "Closing connection: " << message << std::endl;
//         _socket.cancel();
//         _socket.close();
//     }
// };

};
#include <functional>
#include <iostream>
#include <memory>
#include <chrono>
#include <mutex>
#include <deque>
#include <array>
#include <cstdlib>

#include "smallsha1/sha1.h"
#include "cppcodec/base64_default_rfc4648.hpp"
#include "httpparser/request.h"
#include "httpparser/httprequestparser.h"
#include "wscpp/http/header.hpp"
#include "wscpp/http/response.hpp"
#include "wscpp/http/status_code.hpp"
#include "asio.hpp"
#include "wscpp/protocol/frame.hpp"
#include "wscpp/logging.hpp"
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

/**
 * @brief Different rules apply, especially with regards to closing of
 * connections when the connection is either the client or the server-side.
 *
 */
enum class connection_type {
    server,
    client
};

/**
 * @brief The connection can be in strictly one of 5 different states.
 *
 */
enum class connection_state {
    pending,
    handshake,
    open,
    closing,
    closed
};

/**
 * @brief Parameters that can be passed to the constructor of a
 * websocket_connection.
 *
 */
struct params {
    asio::io_context& io_context;
    tcp::socket socket;
    connection_type con_type;
    uint close_wait_timeout = 5;
    uint handshake_timeout = 5;
    uint keepalive_interval = 20;
    uint keepalive_timeout = 10;
};

class websocket_connection {
public:
    websocket_connection(params p);

    void start();
    void write(const std::string payload);
    void write(const void* payload, std::size_t length);
    void close(short unsigned int close_status_code);

    void set_binary_message_handler(std::function<void (std::vector<uint8_t>)> handler);
    void set_close_handler(std::function<void (std::optional<short unsigned int> status_code, std::string reason)> handler);
    void set_text_message_handler(std::function<void (std::string)> handler);

    uuids::uuid id();

private:
    protocol::frame& current_frame();

    void binary_frame_handler(protocol::frame& frame);
    void close_frame_handler(protocol::frame& frame);
    void continuation_frame_handler(protocol::frame& frame);
    void ping_frame_handler(protocol::frame& frame);
    void pong_frame_handler(protocol::frame& frame);
    void text_frame_handler(protocol::frame& frame);

    void frame_handler(const asio::error_code& ec, std::size_t bytes_transferred);
    void handshake_handler(const asio::error_code& ec, std::size_t bytes_transferred);

    void close_wait_timeout_handler(const asio::error_code& ec);
    void handshake_timeout_handler(const asio::error_code& ec);

    void keepalive_handler(const asio::error_code& ec);

    void send_close_frame(short unsigned int close_status_code, bool terminate);
    void start_close_wait_timeout();
    void start_keepalive();
    void start_reading();
    void queue_write_frame(protocol::frame frame);
    void write_pending_frames();

    void keepalive_timeout_handler(const asio::error_code& ec);
    void set_keepalive_timeout();

    std::vector<uint8_t> _buffer;
    tcp::socket _socket;
    asio::io_context& _io_context;
    std::function<void (std::vector<uint8_t>)> _binary_handler;
    std::function<void (std::optional<short unsigned int> status_code, std::string reason)> _close_handler;
    std::function<void (std::string)> _text_handler;

    // timers and timeouts
    asio::steady_timer _close_wait_timer;
    asio::steady_timer _handshake_timer;
    asio::steady_timer _keepalive_timer;
    asio::steady_timer _keepalive_timeout_timer;
    uint _close_wait_timeout;
    uint _handshake_timeout;
    uint _keepalive_interval;
    uint _keepalive_timeout;

    std::recursive_mutex _mutex;

    // Ping payload of the last ping that was sent on this connection
    std::vector<uint8_t> _ping_payload;

    bool _write_in_progress;
    std::vector<protocol::frame> _frames;
    std::deque<protocol::frame> _write_frames;
    std::optional<const protocol::frame> _write_hold_frame;
    std::optional<protocol::enums::opcode> _current_opcode;

    std::vector<uint8_t> _ping_frame_payload;

    connection_type _connection_type;
    connection_state _connection_state;

    uuids::uuid _id;
};

uuid generate_uuid() {
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
    _id(generate_uuid()),
    _io_context(p.io_context),
    _close_wait_timer(p.io_context),
    _handshake_timer(p.io_context),
    _keepalive_timer(p.io_context),
    _close_wait_timeout(p.close_wait_timeout),
    _keepalive_timeout_timer(p.io_context),
    _handshake_timeout(p.handshake_timeout),
    _keepalive_interval(p.keepalive_interval),
    _keepalive_timeout(p.keepalive_timeout),
    _connection_type(p.con_type),
    _connection_state(connection_state::pending),
    _ping_frame_payload()
{};

void websocket_connection::set_binary_message_handler(std::function<void (std::vector<uint8_t>)> handler) {
    _binary_handler = handler;
};


void websocket_connection::set_close_handler(std::function<void (std::optional<short unsigned int> status_code, std::string reason)> handler) {
    _close_handler = handler;
};


void websocket_connection::set_text_message_handler(std::function<void (std::string)> handler) {
    _text_handler = handler;
};

void websocket_connection::start() {
    std::scoped_lock lock_guard(_mutex);
    _connection_state = connection_state::handshake;
    _handshake_timer.expires_after(std::chrono::seconds(_handshake_timeout));
    _handshake_timer.async_wait(std::bind(&websocket_connection::handshake_timeout_handler, this, _1));
    _socket.async_read_some(asio::buffer(_buffer, buffer_size), std::bind(&websocket_connection::handshake_handler, this, _1, _2));
};

void websocket_connection::start_keepalive() {
    _keepalive_timer.expires_after(std::chrono::seconds(_keepalive_interval));
    _keepalive_timer.async_wait(std::bind(&websocket_connection::keepalive_handler, this, _1));
};

void websocket_connection::start_reading() {
    _socket.async_read_some(asio::buffer(_buffer, buffer_size), std::bind(&websocket_connection::frame_handler, this, _1, _2));
};

uuids::uuid websocket_connection::id() {
    return _id;
}

/**
 * @brief Called after the client has waited longer than the timeout for the
 * server to shut down the socket connection.
 *
 * @param ec 
 */
void websocket_connection::close_wait_timeout_handler(const asio::error_code& ec)
{
    if (!ec) {
        std::scoped_lock lock_guard(_mutex);
        if (_connection_state != connection_state::closed) {
            _socket.shutdown(_socket.shutdown_both);
            _connection_state = connection_state::closed;
        }
    }
};

/**
 * @brief Handler that is called when the handshake takes longer than the
 * timeout. Since there is no websocket connection at this point, the socket is
 * closed and the connection state is changed to closed.
 *
 * @param ec 
 */
void websocket_connection::handshake_timeout_handler(const asio::error_code& ec)
{
    if (!ec) {
        LOG_INFO("Handshake timed out. Closing connection.");
        std::scoped_lock lock_guard(_mutex);

        // Since the connection failed to establish a websocket connection, it
        // is under no obligation to send a close frame before shutting down the
        // socket.
        _socket.shutdown(_socket.shutdown_both);
        _connection_state = connection_state::closed;
    }
};

/**
 * @brief Set the timeout timer that will close the connection if the other
 * party does not respond to the ping with a pong.
 *
 */
void websocket_connection::set_keepalive_timeout() {
    _keepalive_timeout_timer.expires_after(std::chrono::seconds(_keepalive_timeout));
    _keepalive_timeout_timer.async_wait(std::bind(&websocket_connection::keepalive_timeout_handler, this, _1));
};

/**
 * @brief Handler that is called when a ping frame is sent but the other party
 * takes too long to reply. At this point the websocket connection should be
 * closed.
 *
 * @param ec 
 */
void websocket_connection::keepalive_timeout_handler(const asio::error_code& ec) {
    if (!ec) {
        std::lock_guard lock_guard(_mutex);
        if (_connection_state != connection_state::closed) {
            send_close_frame(protocol::close_status_code::protocol_error, false);
        }
    }
};

void websocket_connection::keepalive_handler(const asio::error_code& ec) {
    if (!ec) {
        auto frame = protocol::make_ping_frame();
        _ping_frame_payload = frame.data();
        std::lock_guard lock_guard(_mutex);

        _write_frames.push_front(std::move(frame));
        write_pending_frames();
        set_keepalive_timeout();
    }
};

/**
 * @brief Search through the headers and return the value of the
 * 'Sec-Websocket-Key' header
 *
 * @param headers 
 * @return std::string 
 */
std::string sec_websocket_key(const std::vector<httpparser::Request::HeaderItem>& headers) {
    for (auto& header : headers) {
        if (header.name == "Sec-WebSocket-Key") {
            return header.value;
        }
    }
    return "";
};

/**
 * @brief Create the Sec-Websocket-Accept header value that is sent as a
 * response to finish the handshake.
 *
 * @param sec_websocket_key 
 * @return auto 
 */
auto create_sec_websocket_accept(const std::string& sec_websocket_key) {
    std::string raw_sec_websocket_accept = sec_websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char hash[20];
    sha1::calc(raw_sec_websocket_accept.data(), raw_sec_websocket_accept.size(), hash);
    return base64::encode(hash, 20);
};

void websocket_connection::handshake_handler(const asio::error_code& ec, std::size_t bytes_transferred)
{
    _handshake_timer.cancel();
    if (!ec) {
        Request request;
        HttpRequestParser parser;

        HttpRequestParser::ParseResult res = parser.parse(
            request,
            reinterpret_cast<const char *>(_buffer.data()),
            reinterpret_cast<const char *>(_buffer.data()) + bytes_transferred
        );
        if (res == HttpRequestParser::ParseResult::ParsingCompleted) {
            if (request.method == "GET") {
                const auto key = sec_websocket_key(request.headers);
                if (key.empty()) {
                    LOG_ERROR("No Sec-Websocket-Key sent in the handshake request");
                    std::scoped_lock lock_guard(_mutex);
                    _socket.shutdown(_socket.shutdown_both);
                    _connection_state = connection_state::closed;
                    return;
                }

                std::vector<http::header> headers;
                headers.emplace_back(http::header("Upgrade", "websocket"));
                headers.emplace_back(http::header("Connection", "Upgrade"));
                headers.emplace_back(http::header("Sec-Websocket-Accept", create_sec_websocket_accept(key)));
                http::response response(http::status_code::switching_protocols, std::move(headers), "");
                asio::async_write(_socket, response.to_buffers(), [this](const std::error_code& ec, std::size_t){
                    if (!ec) {
                        start_reading();
                        start_keepalive();
                    } else {
                        LOG_ERROR("Error sending handshake response: " << ec.message());
                    }
                });
            } else {
                LOG_ERROR("Invalid request method: " << request.method);
                std::scoped_lock lock_guard(_mutex);
                _socket.shutdown(_socket.shutdown_both);
                _connection_state = connection_state::closed;
                return;
            }
        } else {
            LOG_ERROR("Parsing Error: Closing the connection");
            std::scoped_lock lock_guard(_mutex);
            _socket.shutdown(_socket.shutdown_both);
            _connection_state = connection_state::closed;
            return;
        }
    } else {
        LOG_ERROR("An error occurred while trying to handle the handshake: " << ec.message());
        std::scoped_lock lock_guard(_mutex);
        _socket.shutdown(_socket.shutdown_both);
        _connection_state = connection_state::closed;
        return;
    }
};

protocol::frame& websocket_connection::current_frame() {
    if (_frames.size() == 0 || _frames.back().completed()) {
        _frames.push_back(protocol::frame());
    }

    return _frames.back();
};

std::optional<short unsigned int> parse_close_status_code(protocol::frame& frame) {
    auto& payload = frame.data();
    if (payload.size() >= 2) {
        short unsigned int status_code = 0;
        status_code |= payload[0] << 8;
        status_code |= payload[1];
        return std::make_optional(status_code);
    } else {
        return std::nullopt;
    }
};


/**
 * @brief Handle a binary frame that was received over the connection. Some
 * state checking is done to check if the connection is in the correct state to
 * receive a binary frame.
 *
 * @param frame 
 */
void websocket_connection::binary_frame_handler(protocol::frame& frame) {
    if (_current_opcode) {
        LOG_ERROR("New binary frame received while still processing continuation frames. Sending Close frame.");
        send_close_frame(protocol::close_status_code::protocol_error, false);
        return;
    } else if (frame.final()) {
        // Move the frame into the binary handler so that we can pop it off the
        // stack and call the destructor.
        _binary_handler(std::move(frame.data()));
        _frames.pop_back();
    } else {
        // Leave the current frame on the stack so that we can use it in a
        // continuation frame in the future
        _current_opcode.emplace(opcode::binary);
    }
};


/**
 * @brief Handle close frame that was received over the connection. If the
 * connection is already in the closing state we can shut down the socket if it
 * is the server-side of the connection or we can wait for the socket to be shut
 * down if it is the client-side of the connection.
 *
 * @param frame 
 */
void websocket_connection::close_frame_handler(protocol::frame& frame) {
    if (_connection_state == connection_state::closing) {
        // If we've already sent a close frame then this is
        // just the response to that close frame. In the
        // case of the server, we may now shutdown the
        // socket.
        if (_connection_type == connection_type::server) {
            LOG_DEBUG("Close frame received. Shutting down socket.");
            _socket.shutdown(_socket.shutdown_both);
            return;
        } else {
            LOG_DEBUG("Close frame received. Setting close wait timeout.");
            start_close_wait_timeout();
            return;
        }
    } else {
        // The connection is not yet in the closing state. The connection should
        // respond with a close frame and set the connection state to closing.
        auto status_code = parse_close_status_code(frame);
        if (status_code) {
            // The opposite party wants to close the
            // connection. Send an acknowledgement with the
            // same close reason code.
            send_close_frame(status_code.value(), true);
            return;
        } else {
            // If we can't parse the status code that was
            // sent, send a protocol_error status code
            send_close_frame(protocol::close_status_code::protocol_error, true);
            return;
        }
    }
};


/**
 * @brief Handle a ping frame that is received over the connection. Responds
 * with a pong with the same payload as the ping.
 *
 * @param frame
 */
void websocket_connection::ping_frame_handler(protocol::frame& frame) {
    auto& frame_data = frame.data();
    protocol::frame pong_frame(std::move(frame_data), frame_data.size(), protocol::enums::opcode::pong, true);

    // Push the frame onto the front of the queue so that it is ahead of all
    // other frames. Pings should be responded to as soon as possible and should
    // take priority over other frames.
    _write_frames.push_front(std::move(pong_frame));
    write_pending_frames();
    _frames.pop_back();
};


/**
 * @brief Handle a pong frame that is received over the connection. The payload
 * of the pong should match the payload of the ping frame that was sent out.
 *
 * @param frame
 */
void websocket_connection::pong_frame_handler(protocol::frame& frame) {
    auto& frame_data = frame.data();

    // If the pong response payload does not match the payload of the ping frame
    // that was sent out we should close the connection with a protocol error.
    if (frame_data != _ping_frame_payload) {
        LOG_ERROR("Pong payload did not match payload of ping frame that was sent out. Closing the connection.");
        send_close_frame(protocol::close_status_code::protocol_error, false);
    } else {
        // Restart the keepalive loop.
        start_keepalive();
    }
    _frames.pop_back();
};


/**
 * @brief Handle continuation frame that was received over the connection. If
 * the frame is final, append all the payloads in the frame together and pass
 * this combined payload into the binary or text handlers respectively.
 *
 * @param frame 
 */
void websocket_connection::continuation_frame_handler(protocol::frame& frame) {
    if (!_current_opcode) {
        LOG_ERROR("Continuation frame received but no current opcode being processed. Closing connection.");
        send_close_frame(protocol::close_status_code::protocol_error, false);
        return;
    }

    if (frame.final()) {
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
                full_payload.insert(std::end(full_payload), std::begin(frame_data), std::end(frame_data));
            }

            _binary_handler(std::move(full_payload));
        } else if (_current_opcode == opcode::text) {
            std::string full_payload;
            for (size_t i = 0; i < _frames.size(); i++)
            {
                auto& frame_data = _frames[i].data();
                full_payload.insert(std::end(full_payload), std::begin(frame_data), std::end(frame_data));
            }

            _text_handler(std::move(full_payload));
        }

        _frames.clear();
        _current_opcode.reset();
        return;
    }
};


/**
 * @brief Handle a text frame that was received over the connection. Some state
 * checking is done to check if the connection is in the correct state to
 * receive a text frame.
 *
 * @param frame 
 */
void websocket_connection::text_frame_handler(protocol::frame& frame) {
    if (_current_opcode) {
        LOG_ERROR("New text frame received while still processing continuation frames. Closing the connection.");
        send_close_frame(protocol::close_status_code::protocol_error, false);
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
        _current_opcode.emplace(opcode::text);
    }
};


void websocket_connection::frame_handler(const asio::error_code& ec, std::size_t bytes_transferred)
{
    if (!ec) {
        std::lock_guard lock_guard(_mutex);

        std::error_code frame_error;

        std::size_t bytes_consumed = 0;
        while (bytes_consumed < bytes_transferred) {
            auto& frame = current_frame();
            bytes_consumed += frame.consume(_buffer.data() + bytes_consumed, bytes_transferred, frame_error);
            if (frame.completed()) {
                LOG_INFO("Frame received: " << frame.to_string());
                switch (frame.opcode())
                {
                case opcode::binary:
                    binary_frame_handler(frame);
                    break;
                case opcode::close:
                    close_frame_handler(frame);
                    break;
                case opcode::continuation:
                    continuation_frame_handler(frame);
                    break;
                case opcode::ping:
                    ping_frame_handler(frame);
                    break;
                case opcode::pong:
                    pong_frame_handler(frame);
                    break;
                case opcode::text:
                    text_frame_handler(frame);
                    break;
                default:
                    break;
                }
            }
        }
        start_reading();
    } else if (ec.value() == asio::error::eof) {
        if (_connection_state == connection_state::closed) {
            LOG_DEBUG("EOF from closed connection. Ignoring.");
            return;
        } else if (_connection_state == connection_state::closing) {
            LOG_DEBUG("Got EOF on closing connection. Calling shutdown on the underlying socket.");
            _close_wait_timer.cancel();
            _socket.shutdown(_socket.shutdown_both);
            _connection_state = connection_state::closed;
            return;
        }
    } else {
        LOG_ERROR("An error occurred: " << ec.message() << "\n");
        _socket.shutdown(_socket.shutdown_both);
        return;
    }
};


/**
 * @brief Write a string payload to the connection. This string payload will be
 * broken down into a text frame and potentially multiple continuation frames if
 * the payload is bigger than the max_frame_size.
 *
 * @param message 
 */
void websocket_connection::write(const std::string message) {
    std::vector<protocol::frame> frames;
    auto first_frame(true);
    auto ptr = message.begin();
    while (ptr < message.end()) {
        auto end = std::min(ptr + max_frame_size, message.end());
        auto last_frame = end == message.end();
        std::vector<uint8_t> payload(ptr, end);
        frames.emplace_back(
            std::move(payload),
            payload.size(),
            first_frame ? protocol::enums::opcode::text : protocol::enums::opcode::continuation,
            last_frame
        );

        ptr = end;
        first_frame = false;
    }

    std::lock_guard lock_guard(_mutex);

    for (std::size_t i = 0; i < frames.size(); i++){
        _write_frames.push_back(std::move(frames[i]));
    }

    write_pending_frames();
};


/**
 * @brief Write a binary payload to the connection. If the binary payload
 * exceeds the max_frame_size, the binary payload will automatically be broken
 * up into a binary frame and potentially multiple continuation frames.
 *
 * @param payload 
 * @param length 
 */
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

    std::lock_guard lock_guard(_mutex);

    for (std::size_t i = 0; i < frames.size(); i++){
        _write_frames.push_back(std::move(frames[i]));
    }

    write_pending_frames();
};

/**
 * @brief Asynchronously write pending frames to the underlying socket.
 *
 * NB: This method should only be called from a context where the _mutex
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
        std::lock_guard lock_guard(_mutex);
        _write_in_progress = false;

        if (!ec) {
            if (_write_hold_frame->get_terminate()) {
                // If the terminate boolean is set on the frame and this is the
                // server-side of the connection, the socket connection should
                // be closed 
                if (_connection_type == connection_type::server) {
                    _socket.shutdown(_socket.shutdown_both);
                    _connection_state = connection_state::closed;
                } else {
                    start_close_wait_timeout();
                }

                // TODO: Call websocket terminate handler
            } else if (_write_frames.size() > 0) {
                // If there are more pending frames to write, call the method
                // again
                write_pending_frames();
            }
        } else if (ec.value() != asio::error::operation_aborted) {
            // TODO: Log the aborted message
        }
    });
};

/**
 * @brief In the case of the client-side of the connection, set a
 *  timeout and wait for the server-side to shut down the socket.
 *  Once the socket shuts down a asio::error::eof is received by
 *  the frame_handler. At this point, the client may also call
 *  shutdown and destroy the socket. If the server takes longer
 *  than the timeout, the socket will be shut down.
 */
void websocket_connection::start_close_wait_timeout() {
    _close_wait_timer.expires_after(std::chrono::seconds(_close_wait_timeout));
    _close_wait_timer.async_wait(std::bind(&websocket_connection::close_wait_timeout_handler, this, _1));
};

/**
 * @brief Send a close frame with a status code. Optionally close the socket
 * connection once the frame has been sent.
 *
 * @param close_status_code Close status code as defined in RFC6455
 * @param terminate A boolean indicating whether to close the socket connection
 * after the close frame is sent.
 */
void websocket_connection::send_close_frame(short unsigned int close_status_code, bool terminate) {
    auto close_frame = protocol::make_close_frame(close_status_code);

    if (terminate) {
        // Set the terminate flag on the frame so that the write method knows to
        // close the socket connection once the frame has been sent.
        close_frame.set_terminate(true);
    } else {
        start_close_wait_timeout();
    }

    _connection_state = connection_state::closing;

    // Clear all frames that are waiting to be written. We won't be sending them
    // anyway after the close frame is sent.
    _write_frames.clear();
    _write_frames.push_back(std::move(close_frame));

    write_pending_frames();
};

void websocket_connection::close(short unsigned int close_status_code) {
    std::lock_guard lock(_mutex);
    send_close_frame(close_status_code, false);
};

};
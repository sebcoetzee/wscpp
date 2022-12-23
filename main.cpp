#include <functional>
#include <array>
#include <iostream>
#include <memory>
#include <utility>
#include <type_traits>
#include <unordered_set>
#include <iostream>
#include <chrono>
#include <cstdlib>

#include <cppcodec/base64_default_rfc4648.hpp>
#include <httpparser/request.h>
#include <httpparser/httprequestparser.h>
#include "wscpp/connection.hpp"
#include "wscpp/http/header.hpp"
#include "wscpp/http/response.hpp"
#include "wscpp/http/status_code.hpp"
#include "wscpp/protocol/frame.hpp"
#include <asio.hpp>

using asio::ip::tcp;

using namespace std::placeholders;
using namespace httpparser;

static unsigned int id_counter = 0;

namespace wscpp {

class tcp_server : public std::enable_shared_from_this<tcp_server> {
public:
    static auto create(asio::io_context& io_context, int port);
    void remove_connection(std::shared_ptr<websocket_connection> websocket_connection);
private:
    tcp_server(asio::io_context& io_context, int port);
    void accept_callback_handler(const asio::error_code& ec, tcp::socket&& socket);
    std::unordered_set<std::shared_ptr<websocket_connection>> _websocket_connections;
    asio::io_context & _io_context;
    tcp::acceptor _acceptor;
};

auto tcp_server::create(asio::io_context& io_context, int port)
{
    std::cout << "Create server..." << std::endl;
    return std::shared_ptr<tcp_server>(new tcp_server(io_context, port));
};

tcp_server::tcp_server(asio::io_context& io_context, int port) :_io_context(io_context), _acceptor(io_context, tcp::endpoint(tcp::v4(), port))
{
    _acceptor.async_accept(std::bind(&tcp_server::accept_callback_handler, this, _1, _2));
};

void tcp_server::remove_connection(std::shared_ptr<websocket_connection> websocket_connection) {
    _websocket_connections.erase(websocket_connection);
    std::cout << "Connections: " << _websocket_connections.size() << std::endl;
}

void text_handler(std::shared_ptr<websocket_connection> connection, std::string message) {
    std::cout << "Handling text message.\n";
    std::cout << message << "\n";
    std::cout << "Sending the same message payload back to the client.\n";
    connection->write(message);
}

void tcp_server::accept_callback_handler(const asio::error_code& ec, tcp::socket&& socket) {
    std::cout << "New connection: " << socket.remote_endpoint().address() << ":" << socket.remote_endpoint().port() << std::endl;
    std::shared_ptr<websocket_connection> connection(new websocket_connection({.io_context = _io_context, .socket = std::move(socket)}));
    connection->set_text_message_handler(std::bind(text_handler, connection, std::placeholders::_1));
    connection->start();
    this->_websocket_connections.insert(connection);

    std::cout << "Connections: " << this->_websocket_connections.size() << std::endl;
    _acceptor.async_accept(std::bind(&tcp_server::accept_callback_handler, this, _1, _2));
};

};


int main()
{
    srand((unsigned) time(NULL));

    asio::io_context io;
    auto server = wscpp::tcp_server::create(io, 8080);
    io.run();

    return 0;
};
#pragma once

#include <chrono>
#include <iomanip>
#include <iostream>

#include "string.h"

#define _FILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define WSCPP_LOG_LEVEL_NO_LOG    0x00
#define WSCPP_LOG_LEVEL_ERROR     0x01
#define WSCPP_LOG_LEVEL_INFO      0x02
#define WSCPP_LOG_LEVEL_DEBUG     0x03

// Set default log level
#ifndef WSCPP_LOG_LEVEL
#define WSCPP_LOG_LEVEL WSCPP_LOG_LEVEL_NO_LOG
#endif

std::string timestamp() {
    using namespace std::chrono;

    auto now = system_clock::now();

    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = system_clock::to_time_t(now);
    std::tm bt = *std::localtime(&timer);

    std::ostringstream stream;
    stream << std::put_time(&bt, "%FT%H:%M:%S");
    stream << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return stream.str();
}

#define PRINT_MESSAGE(stream, level, message)   auto now = std::chrono::system_clock::now(); \
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
    const char* filename = _FILE; \
    (stream) << timestamp() << " " << (level) << " " << filename << "(" << __LINE__ << ") --> '" << message << "'\n"

#if WSCPP_LOG_LEVEL >= WSCPP_LOG_LEVEL_DEBUG
#define LOG_DEBUG(message)  PRINT_MESSAGE(std::cout, "DEBUG", message)
#else
#define LOG_DEBUG(message)
#endif

#if WSCPP_LOG_LEVEL >= WSCPP_LOG_LEVEL_INFO
#define LOG_INFO(message)   PRINT_MESSAGE(std::cout, "INFO ", message)
#else
#define LOG_INFO(message)
#endif

#if WSCPP_LOG_LEVEL >= WSCPP_LOG_LEVEL_ERROR
#define LOG_ERROR(message)  PRINT_MESSAGE(std::cerr, "ERROR", message)
#else
#define LOG_ERROR(message)
#endif
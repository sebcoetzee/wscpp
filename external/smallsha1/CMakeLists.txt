add_library(smallsha1 INTERFACE)

target_sources(smallsha1 INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/sha1.cpp)
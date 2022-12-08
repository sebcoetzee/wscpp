cmake_minimum_required(VERSION 3.25.0)

project(websockets)
SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(include)
add_subdirectory(external/smallsha1)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(main main.cpp)

target_link_libraries(main ${CONAN_LIBS} includes smallsha1)
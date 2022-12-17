add_subdirectory(smallsha1)

add_library(wscpp_external INTERFACE)

target_include_directories(wscpp_external INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(wscpp_external INTERFACE smallsha1)
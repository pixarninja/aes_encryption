cmake_minimum_required(VERSION 3.0.2)
project (aes_encryption)

set( CMAKE_EXPORT_COMPILE_COMMANDS on )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11 -g -Wpedantic")
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_executable(encrypt aes.cpp round.cpp)
target_link_libraries(encrypt m)

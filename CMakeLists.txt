cmake_minimum_required(VERSION 3.23)
project(untitled4)

set(CMAKE_CXX_STANDARD 14)

include_directories("C:/Program Files/Npcap/Include")
link_directories("C:/Program Files/Npcap/Lib")

add_executable(untitled4 main.cpp)
target_link_libraries(untitled4 wpcap Packet)
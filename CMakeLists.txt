cmake_minimum_required(VERSION 3.26)
project(RabbitCipher)

set(CMAKE_CXX_STANDARD 17)

add_executable(RabbitCipher main.cpp
        RabbitCipher_lib/Rabbit.h
        RabbitCipher_lib/Rabbit.cpp
        RabbitCipher_lib/utils.cpp
        RabbitCipher_lib/utils.h)

include_directories(RabbitCipher_lib)
add_subdirectory(RabbitCipher_lib)
add_subdirectory(Google_tests)
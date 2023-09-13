project(Google_tests)

set(HEADER_FILES
        Rabbit.h
)

set(SOURCE_FILES
        Rabbit.cpp
)

add_library(RabbitCipher_lib STATIC ${SOURCE_FILES} ${HEADER_FILES})
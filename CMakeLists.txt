cmake_minimum_required(VERSION 3.25)

enable_language(C CXX)

project(AsyncChatServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.88.0 REQUIRED COMPONENTS system)
find_package(OpenSSL 3.0.0 REQUIRED)

add_library(sqlite3 STATIC thirdparty/sqlite/sqlite3.c)
target_include_directories(sqlite3 PUBLIC thirdparty/sqlite)

include_directories(
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    thirdparty/sqlite
    include
)

add_executable(AsyncChatServer
    src/main.cpp
    src/protocol.cpp
    src/logger.cpp
    src/db_manager.cpp
    src/server.cpp
    src/session.cpp
)

target_link_libraries(AsyncChatServer
    PRIVATE
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    sqlite3
)

if(WIN32)
    target_link_libraries(AsyncChatServer PRIVATE crypt32 ws2_32)
endif()

if(UNIX AND NOT APPLE)
    target_link_libraries(AsyncChatServer PRIVATE pthread dl)
endif()
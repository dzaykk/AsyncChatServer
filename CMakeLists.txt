cmake_minimum_required(VERSION 3.25)

cmake_policy(SET CMP0144 OLD)
cmake_policy(SET CMP0167 OLD)
enable_language(C)

project(AsyncChatServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-D_WIN32_WINNT=0x0601)

set(BOOST_ROOT "C:/local/boost_1_88_0")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.88.0 REQUIRED COMPONENTS system)

set(OPENSSL_ROOT_DIR "C:/local/OpenSSL-Win64")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.5.0 REQUIRED)

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
    crypt32
)
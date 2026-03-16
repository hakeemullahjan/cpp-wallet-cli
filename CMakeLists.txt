cmake_minimum_required(VERSION 3.16)
project(wallet LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(wallet
    src/main.cpp
    src/wallet.cpp
)

target_include_directories(wallet PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(wallet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

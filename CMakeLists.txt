cmake_minimum_required(VERSION 2.8.11.2 FATAL_ERROR)
set(CMAKE_CXX_FLAGS "-Wall -std=gnu++11")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_DEBUG "-pg -g3 -ggdb")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(utils)
include(cpu)
include(add_boost)
include(add_openssl)
#include( add_cryptopp )

link_directories(${BoostSourceDir}/stage/lib)
include_directories(src)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
    
#include_directories( ${CryptoPP_INCLUDE_DIR} )
#add_executable(test src/Certificate.cpp)
#target_link_libraries( test
#	${CryptoPP_LIBRARY}
#)
add_library(539proj1 src/Certificate.cpp src/PublicKey.cpp)

add_executable(proj1 src/main.cpp src/Certificate.cpp )
target_link_libraries(proj1
    539proj1
    ${BoostSystemLibs} 
    ${BoostFilesystemLibs}
    ${BoostProgramOptionsLibs}
    ${BoostRegexLibs}
    crypto
    ssl
    dl
    )

enable_testing()

add_executable(test_encrypt test_key.cpp)
target_link_libraries(test_encrypt
    539proj1
    ${BoostSystemLibs} 
    ${BoostFilesystemLibs}
    ${BoostProgramOptionsLibs}
    ${BoostRegexLibs}
    crypto
    ssl
    dl
    )
add_test(encrypt test_encrypt ../certificate/public_ket.pem)

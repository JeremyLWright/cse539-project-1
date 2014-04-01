cmake_minimum_required(VERSION 2.8.11.2 FATAL_ERROR)
set(CMAKE_CXX_FLAGS "-Wall -std=gnu++11")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_DEBUG "-pg")

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(utils)
include(cpu)
include(add_boost)
include(add_nss)

message("Modules ${CMAKE_SOURCE_DIR} 
Boost Source: ${BoostSourceDir} 
Boost Date Time: ${BoostDateTimeLibs} 
${BoostFilesystemLibs}
Regex: ${BoostRegexLibs}.")
link_directories(${BoostSourceDir}/stage/lib)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
    
add_executable(proj1 main.cpp)
target_link_libraries(proj1
    ${BoostSystemLibs} 
    ${BoostFilesystemLibs}
    ${BoostProgramOptionsLibs}
    ${BoostRegexLibs}
    nss3
    )

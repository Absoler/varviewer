cmake_minimum_required(VERSION 3.10)

project(extracter)

message(STATUS ${PROJECT_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/thirdparty/nlohmann)
include_directories(${PROJECT_SOURCE_DIR}/src/include)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)

add_subdirectory(src)
# ----------------------------------------------------------
# Common
# ----------------------------------------------------------

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

# ----------------------------------------------------------
# Project variables and paths
# ----------------------------------------------------------

# Project name
project(sd-aes-attacks)

# Store variables
set(PROJECT_CHECK_RESULTS_DIR check)
set(PROJECT_SOURCE_DIR src)
set(PROJECT_TESTS_DIR tests)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(INCLUDE_DIRECTORIES include src)

# Add include paths
include_directories(${INCLUDE_DIRECTORIES})

# Stores all executables in src folder into variable SOURCES
file(GLOB_RECURSE SOURCES "${PROJECT_SOURCE_DIR}/ciphers/*.cc" "${PROJECT_SOURCE_DIR}/utils/*.cc")

# Stores all executables in src folder into variable TESTS
file(GLOB TESTS "${PROJECT_TESTS_DIR}/*.cc")

# Compile flags
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -pedantic -std=c++11 -mavx -march=native -O3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb3 -DDEBUG -fsanitize=undefined,alignment,address -ftrapv -fno-omit-frame-pointer -fno-optimize-sibling-calls")
# -Wconversion -Wsign-conversion -Werror

set(CMAKE_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE) 
    set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

# Logging
message("Using build type ${CMAKE_BUILD_TYPE}")

# check for jsoncpp version
find_package(PkgConfig REQUIRED)

# ----------------------------------------------------------
# libraries
# ----------------------------------------------------------

# Include pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Include GoogleTest
find_package(GTest REQUIRED)

# ----------------------------------------------------------
# Building apps
# ----------------------------------------------------------

# Builds all files "xx.cc" in tests folder to executable "xx"
foreach(tests_file ${TESTS})
    # Replace cc from "xx.cc" to get executable name "xx"
    string(REPLACE ".cc" "" filename_without_extension ${tests_file})
    string(REPLACE "${CMAKE_SOURCE_DIR}/${PROJECT_TESTS_DIR}/" "" filename_without_extension ${filename_without_extension})

    add_executable(${filename_without_extension} ${tests_file} ${SOURCES} ${INCLUDE_DIRECTORIES})
    
    # Link against gtest, pthreads and
    target_link_libraries(${filename_without_extension} Threads::Threads gtest gtest_main)
endforeach(tests_file ${TESTS})

# ----------------------------------------------------------
# Special build targets for checking, tidying, formatting
# ----------------------------------------------------------

# Check
add_custom_target(
    clang-check
    COMMAND /usr/bin/clang-check
    ${SOURCES}
    --
    -I${INCLUDE_DIRECTORIES}
    -std=c++11
)

# Tidy
add_custom_target(
    clang-tidy
    COMMAND /usr/bin/clang-tidy
    ${SOURCES}
    --
    -std=c++11
    -I${INCLUDE_DIRECTORIES}
)

# Format
add_custom_target(
    clang-format
    COMMAND /usr/bin/clang-format
    -style=file
    -i
    ${SOURCES}
    -I${INCLUDE_DIRECTORIES}
)

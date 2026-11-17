cmake_minimum_required(VERSION 3.16)
project(SentinelFlow VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find libpcap
find_library(PCAP_LIBRARY pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)

# Main library (all source files except main.cpp)
file(GLOB_RECURSE LIB_SOURCES
    src/capture/*.cpp
    src/parser/*.cpp
    src/pipeline/*.cpp
    src/detection/*.cpp
    src/alert/*.cpp
    src/stats/*.cpp
    src/utils/*.cpp
)

add_library(sentinelflow_lib STATIC ${LIB_SOURCES})
target_include_directories(sentinelflow_lib PUBLIC include)
target_link_libraries(sentinelflow_lib ${PCAP_LIBRARY})

# Main executable
add_executable(sentinelflow src/main.cpp)
target_link_libraries(sentinelflow sentinelflow_lib)
target_compile_definitions(sentinelflow PRIVATE SENTINELFLOW_VERSION="${PROJECT_VERSION}")

# Tests (optional, controlled by BUILD_TESTING)
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Benchmarks
option(BUILD_BENCH "Build benchmarks" OFF)
if(BUILD_BENCH)
    add_subdirectory(bench)
endif()

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
FetchContent_MakeAvailable(googletest)

# Collect all test sources
file(GLOB TEST_SOURCES test_*.cpp)

add_executable(sentinelflow_tests ${TEST_SOURCES})
target_link_libraries(sentinelflow_tests
    sentinelflow_lib
    GTest::gtest_main
)
target_include_directories(sentinelflow_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

include(GoogleTest)
gtest_discover_tests(sentinelflow_tests)

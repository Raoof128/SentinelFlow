add_executable(benchmark_throughput benchmark_throughput.cpp)
target_link_libraries(benchmark_throughput sentinelflow_lib)

# End-to-end: synthetic frames through the whole pipeline with the default rules.
add_executable(benchmark_pipeline benchmark_pipeline.cpp)
target_link_libraries(benchmark_pipeline sentinelflow_lib)
target_compile_definitions(benchmark_pipeline PRIVATE
    SF_DEFAULT_RULES_PATH="${CMAKE_SOURCE_DIR}/rules/default.rules")

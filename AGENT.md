# AGENT.md — SentinelFlow

## Project Overview
SentinelFlow is a real-time network intrusion detection system (NIDS) built in C++17. It captures live network traffic via libpcap, parses protocol headers, detects known attack signatures using a rule engine and stateful analysis, and logs structured security alerts.

## Architecture
- **Namespace:** All code lives in `sf`
- **Capture:** Abstract `PacketCapture` interface with `LiveCapture` and `PcapFileReader` implementations
- **Parsers:** Per-protocol parsers (Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP) returning structs
- **Detection:** `DetectionEngine` orchestrates `SignatureMatcher`, `PortScanDetector`, `SynFloodDetector`, `DnsTunnelDetector`
- **Alerting:** `AlertManager` dispatches to pluggable `AlertOutput` implementations (`ConsoleLogger`, `CsvLogger`)
- **Stats:** `TrafficStats` tracks per-protocol packet/byte counters

## Conventions
- C++17 standard, `#pragma once` for headers
- All headers under `include/sentinelflow/`, implementations under `src/`
- Network byte-order: always use `ntohs()`/`ntohl()` for multi-byte fields
- Buffer safety: always check `length` before parsing
- RAII for pcap handles
- Tests use Google Test (gtest, fetched via FetchContent)
- Build system: CMake 3.16+
- Code formatting: `.clang-format` (LLVM-based, 4-space indent, 100-col limit)
- Static analysis: `.clang-tidy` (bugprone, cppcoreguidelines, modernize, performance, readability)
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`
- Error handling: wrap `std::stoul`/`std::stoi` in try-catch for user-facing input parsing

## Build & Test
```bash
cmake -B build -DBUILD_TESTING=ON -DBUILD_BENCH=ON
cmake --build build
cd build && ctest --output-on-failure
```

## Change Log
Raouf:
- Date: 2026-03-21 (AEDT)
- Scope: Full project scaffold
- Summary: Initial implementation of SentinelFlow NIDS — all modules created from blueprint
- Files: 68 files across include/, src/, tests/, bench/, docs/, .github/
- Verification: Project scaffolded, pending build verification
- Follow-ups: Install libpcap, verify build on target platform, add sample .pcap files

Raouf:
- Date: 2026-03-21 (AEDT)
- Scope: Production audit — code quality, docs, CI/CD, tooling
- Summary: Comprehensive audit bringing repo to industry-grade standard
- Files: 20+ files added/modified (see CHANGELOG.md for full list)
- Verification: 27/27 tests pass, clean build, zero warnings
- Follow-ups: Consider adding compiler warning flags (-Wall -Wextra -Wpedantic) to CMakeLists.txt

Raouf:
- Date: 2026-11-17 (AEDT)
- Scope: CI — formatting and the static-analysis job
- Summary: Ran clang-format 17 with the repository .clang-format across include/, src/, tests/ and bench/ so the format-check job passes; gave the advisory clang-tidy step per-file and step time limits so it no longer runs to the six-hour job limit; no behaviour change
- Files: 60 .cpp/.hpp files, .github/workflows/ci.yml, CHANGELOG.md, AGENT.md
- Verification: all six CI jobs pass on the pull request; 27/27 tests pass locally
- Follow-ups: .clang-tidy naming options use camelCase, which clang-tidy 17 rejects (expects camelBack); nodiscard and brace findings remain advisory

Raouf:
- Date: 2026-11-17 (AEDT)
- Scope: Parser field reads; README accuracy
- Summary: Replaced pointer-cast field reads in every parser with memcpy-based read_be16/read_be32 (alignment and aliasing safe); corrected the README's "zero-copy" claim and scoped the benchmark description to what it measures
- Files: include/sentinelflow/utils/byte_order.hpp (new), src/parser/*.cpp, README.md, CHANGELOG.md, AGENT.md
- Verification: 27/27 tests pass locally; clang-format 17 clean
- Follow-ups: end-to-end benchmark over a pcap

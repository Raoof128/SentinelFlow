# AGENT.md — SentinelFlow

## Project Overview
SentinelFlow is a real-time network intrusion detection system (NIDS) built in C++17. It captures live network traffic via libpcap, parses protocol headers, detects known attack signatures using a rule engine and stateful analysis, and logs structured security alerts.

## Architecture
- **Namespace:** All code lives in `sf`
- **Capture:** Abstract `PacketCapture` interface with `LiveCapture` and `PcapFileReader` implementations
- **Parsers:** Per-protocol parsers (Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP) returning structs
- **Pipeline:** `parse_packet()` / `process_packet()` (`src/pipeline/`) frame and parse one Ethernet frame, record stats, run detection and dispatch alerts; `main.cpp`, the tests and `bench/benchmark_pipeline` all call it
- **Detection:** `DetectionEngine` orchestrates `SignatureMatcher`, `PortScanDetector`, `SynFloodDetector`, `DnsTunnelDetector`; `apply_rules()` passes rule values to the SYN-flood and DNS-tunnel detectors; per-source state lives in the bounded `SourceTable`
- **Alerting:** `AlertManager` dispatches to pluggable `AlertOutput` implementations (`ConsoleLogger`, `CsvLogger`)
- **Stats:** `TrafficStats` tracks per-protocol packet/byte counters

## Conventions
- C++17 standard, `#pragma once` for headers
- All headers under `include/sentinelflow/`, implementations under `src/`
- Network byte-order: always use `ntohs()`/`ntohl()` for multi-byte fields
- Buffer safety: always check `length` before parsing
- RAII for pcap handles
- Tests use Google Test (gtest, fetched via FetchContent)
- Build system: CMake 3.18+ (`find_library(... REQUIRED)` needs it)
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

Raouf:
- Date: 2026-11-17 (AEDT)
- Scope: Signature matching bug; README known limitations
- Summary: Content rules no longer match packets with no payload (they did, alerting on every bare SYN to the rule's port); README lists the detection code's known limitations
- Files: src/detection/signature_matcher.cpp, tests/test_signature_matcher.cpp, README.md, CHANGELOG.md, AGENT.md
- Verification: 30/30 tests pass locally (3 new); clang-format 17 clean
- Follow-ups: wire rule thresholds to the detectors; evict idle per-source state; end-to-end test and benchmark

Raouf:
- Date: 2026-11-17 (AEDT)
- Scope: Detector correctness, rule handling, packet framing, end-to-end test and benchmark
- Summary: Rule thresholds and DNS length now reach the detectors (`DetectionEngine::apply_rules`); ICMP flood rule removed, no detector exists; stateful detectors use a bounded `SourceTable` (idle eviction, 65,536-entry cap); port-scan window counts only ports seen inside the window; SYN flood alerts once per destination per window; `process_packet` moved into the library (`src/pipeline/`) with IPv4 total-length trimming, fragment skipping and TCP data-offset checks; DNS parser rejects labels over 63 and names over 255, ends the name at a compression pointer and exposes the QR bit, tunnel detector ignores responses; non-Ethernet link types refused; IPv4 CIDR matching and strict rule parsing with counted warnings; end-to-end tests and `bench/benchmark_pipeline`; CMake 3.18 minimum and version 1.1.0 made consistent; README Known Limitations rewritten
- Files: see CHANGELOG.md (new: source_table.hpp, pipeline.hpp/.cpp, link_type.hpp/.cpp, benchmark_pipeline.cpp, 5 test files)
- Verification: 130/130 tests pass locally (30 before); 38 new tests confirmed failing on the unmodified sources first; clang-format 17 clean; ASan/UBSan clean; CI on the pull request
- Follow-ups: ICMP flood detector; configurable port-scan thresholds; VLAN/IPv6 framing; fuzzing and a sanitizer CI job

Raouf:
- Date: 2026-11-17 (AEDT)
- Scope: Two detection bypasses found by a security review of the detector changes
- Summary: DNS tunnel detector no longer trusts the sender-controlled QR bit (a message to port 53 is analysed whatever it claims; only a message from port 53 to another port is a reply); `SourceTable` counts capacity evictions, drops expired records first and picks the least advanced of the 8 oldest live records when full, `DetectionEngine` raises a rate-limited MEDIUM "State table pressure" alert (SID 5100) and `main` prints eviction totals; README Known Limitations says plainly that a bounded table is evadable by an attacker who can spoof enough sources
- Files: see CHANGELOG.md (new: tests/test_source_table.cpp)
- Verification: 146/146 tests pass locally; reverting each fix fails six new tests; clang-format 17 clean; ASan/UBSan clean; CI on the pull request
- Follow-ups: non-heuristic protection against table flushing; tune the eviction group size

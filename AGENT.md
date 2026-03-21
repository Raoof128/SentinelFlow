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
- Tests use Google Test (gtest)
- Build system: CMake 3.16+

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

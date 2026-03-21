# Changelog — SentinelFlow

## [1.0.0] - 2026-03-21

Raouf:
- **Date:** 2026-03-21 (AEDT)
- **Scope:** Full project — initial implementation
- **Summary:** Built complete SentinelFlow NIDS from blueprint specification
  - Packet capture engine (live + pcap file replay) via libpcap
  - Protocol parsers: Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP
  - Detection engine: signature matching (Snort-inspired rules), port scan detection, SYN flood detection, DNS tunnelling detection
  - Alert system: colour-coded console output + CSV file logging
  - Traffic statistics with per-protocol counters
  - CLI with --pcap, --rules, --log, --filter options
  - 25+ unit tests (Google Test) + throughput benchmark
  - GitHub Actions CI pipeline
  - MIT License
- **Files changed:** 68 files created
  - `include/sentinelflow/` — 19 header files
  - `src/` — 17 implementation files + main.cpp
  - `tests/` — 11 test files + CMakeLists.txt
  - `bench/` — benchmark + CMakeLists.txt
  - `docs/` — architecture.md, rules_format.md
  - `rules/` — default.rules
  - Root: CMakeLists.txt, README.md, LICENSE, AGENT.md, CHANGELOG.md
  - `.github/workflows/ci.yml`
- **Verification:** Pending build on target platform (requires libpcap-dev)
- **Follow-ups:**
  - Install libpcap and verify full build
  - Add sample .pcap files for testing
  - Initialize git repo and push to GitHub

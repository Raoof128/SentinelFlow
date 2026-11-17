# Changelog — SentinelFlow

## [Unreleased]

Raouf:
- **Date:** 2026-11-17 (AEDT)
- **Scope:** CI — formatting and the static-analysis job
- **Summary:** Ran `clang-format` 17 with the repository `.clang-format` over `include/`, `src/`, `tests/` and `bench/` so the `format-check` CI job passes (whitespace, line wrapping and include order only). The advisory `static-analysis` job used to run until the six-hour limit and get cancelled; each file now runs clang-tidy under `timeout 180` and the step under a 20-minute limit. No behaviour change.
- **Files changed:** 60 `.cpp`/`.hpp` files, .github/workflows/ci.yml, CHANGELOG.md, AGENT.md
- **Verification:** all six CI jobs pass on the pull request (static-analysis in about 4 minutes); local build and `ctest` 27/27 pass
- **Follow-ups:** `.clang-tidy` sets the naming options to `camelCase`, which clang-tidy 17 rejects (it expects `camelBack`); clang-tidy's `nodiscard` and brace findings are advisory and not yet addressed

---

## [1.1.0] - 2026-03-21

Raouf:
- **Date:** 2026-03-21 (AEDT)
- **Scope:** Production audit — code quality, documentation, CI/CD, tooling
- **Summary:** Comprehensive audit bringing repository to industry-grade standard
  - **Code quality fixes:**
    - Added error handling (try-catch) around all `std::stoul`/`std::stoi` calls in rule_parser.cpp and ip_utils.cpp
    - Fixed CSV escaping in csv_logger.cpp (RFC 4180 compliance)
    - Added missing `#include <cstring>` and `#include <arpa/inet.h>` in test_integration.cpp
  - **Documentation:**
    - Rewrote README.md with badges, table of contents, architecture diagram, sample output, detection capabilities table, performance benchmarks, project structure
    - Expanded docs/architecture.md with data flow, detection strategies, threading model, extensibility guide
    - Expanded docs/rules_format.md with flag reference table, additional examples, notes section
    - Added CONTRIBUTING.md with full development guide, code style, commit format, PR process
    - Added CODE_OF_CONDUCT.md (Contributor Covenant)
    - Added SECURITY.md with vulnerability reporting policy
  - **CI/CD:**
    - Upgraded ci.yml: matrix build (g++/clang++ x Debug/Release), clang-format check, clang-tidy static analysis
  - **Tooling configs:**
    - Added .clang-format (LLVM-based, C++17, 4-space indent, 100-col)
    - Added .clang-tidy (bugprone, cppcoreguidelines, modernize, performance, readability)
    - Added .editorconfig (cross-editor consistency)
    - Added .gitattributes (line endings, binary detection, linguist)
    - Added Doxyfile (API documentation generation)
  - **GitHub templates:**
    - Added .github/ISSUE_TEMPLATE/bug_report.md
    - Added .github/ISSUE_TEMPLATE/feature_request.md
    - Added .github/PULL_REQUEST_TEMPLATE.md
- **Files changed:** 20+ files added/modified
  - New: CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, .clang-format, .clang-tidy, .editorconfig, .gitattributes, Doxyfile
  - New: .github/ISSUE_TEMPLATE/bug_report.md, .github/ISSUE_TEMPLATE/feature_request.md, .github/PULL_REQUEST_TEMPLATE.md
  - Modified: README.md, .github/workflows/ci.yml, src/detection/rule_parser.cpp, src/alert/csv_logger.cpp, src/utils/ip_utils.cpp, tests/test_integration.cpp, docs/architecture.md, docs/rules_format.md, AGENT.md
- **Verification:** 27/27 tests pass, clean build, zero warnings
- **Follow-ups:**
  - Add compiler warning flags (-Wall -Wextra -Wpedantic) to CMakeLists.txt
  - Run clang-format across entire codebase
  - Set up Doxygen generation in CI

---

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

# Changelog — SentinelFlow

## [Unreleased]

Raouf:
- **Date:** 2026-11-17 (AEDT)
- **Scope:** Detector correctness, rule handling, packet framing, end-to-end test and benchmark
- **Summary:** A review found that the code did not do what the documentation said. Fixed, each with a test that failed before the change:
  - **Rule options were decorative.** `DetectionEngine` built the detectors with constants and `threshold:` / `dns_query_len:` in a rules file changed nothing. `DetectionEngine::apply_rules()` now passes the SYN-flood rule's threshold and window and the DNS rule's name length (and optional threshold) to the detectors, keeps the old constants as defaults, and warns about any `threshold` rule no detector can use. ICMP flood has no detector and the smaller correct change was to remove its rule from `rules/default.rules` and document it as not implemented. `default.rules` now says `threshold:100,10` for SYN flood, the value the code always used: `20,60` would have flagged the bundled benign `normal_traffic.pcap` (50 handshakes to one server in 50 s) as a flood.
  - **Per-source state grew without bound** and the port-scan timestamp vector erased from the front on every packet. The three stateful detectors now keep their records in a new `SourceTable` that evicts idle entries from the cold end (amortised constant cost) and caps the table at 65,536 entries, dropping the least recently updated; timestamps are in deques, and the port-scan record is an ordered list of (port, last seen).
  - **Port-scan window:** ports were forgotten only when every timestamp expired, so a sender doing one SYN per 50 s accumulated ports across windows and alerted. Only ports seen inside the window now count.
  - **SYN-flood alert storm:** one alert per threshold-th SYN. Now one alert per destination per window while the flood continues. The counting unit is the destination, so the cooldown is per destination too; a per-(source, destination) cooldown would give one alert per spoofed source.
  - **Framing:** `process_packet` moved from `main.cpp` to `src/pipeline/pipeline.cpp` (`parse_packet`, `process_packet`). It trims to the IPv4 total length (Ethernet padding is no longer payload; 0 means use the captured length), skips transport parsing for non-first fragments, and `parse_tcp` / `parse_ipv4` reject a TCP data offset below 5 or beyond the segment and an IHL longer than the buffer. UDP payload is trimmed to the UDP length.
  - **DNS parser:** labels over 63 bytes, names over 255 bytes and unterminated names are rejected; a compression pointer ends the name; QDCOUNT 0 yields no name; `DNSHeader::is_response` exposes the QR bit and the tunnel detector ignores responses.
  - **Link type:** `PcapFileReader` and `LiveCapture` refuse a capture whose link type is not Ethernet, with an error naming it.
  - **Rules:** IPv4 CIDR matching for rule source and destination addresses (it always returned 0 before); strict parsing (negative, overflowing or trailing-garbage numbers, bad addresses, ports, protocols, flags, unknown options and zero thresholds are rejected with a warning that names the line and a rejected count). Rule matching also no longer ignores an address, port or flag condition when the packet has no IPv4, TCP/UDP or TCP header, so a protocol-any port rule cannot fire on a fragment or an ICMP message.
  - **New:** end-to-end tests that run raw frames through the library pipeline, and `bench/benchmark_pipeline` (run in the Release g++ CI job).
  - **Consistency:** CMake minimum raised to 3.18 (`find_library(... REQUIRED)` needs it) in CMakeLists.txt, README, CONTRIBUTING and AGENT.md; version 1.1.0 everywhere (CMake, `sentinelflow` banner via `SENTINELFLOW_VERSION`, Doxyfile); `tools/generate_samples.cpp` has a CMake target and now uses a 2026 timestamp (the sample pcaps were dated 2024, which is why the README sample output was); README sample output is real output; Known Limitations rewritten to what is still true.
- **Files changed:** `include/sentinelflow/detection/source_table.hpp`, `include/sentinelflow/pipeline/pipeline.hpp`, `include/sentinelflow/capture/link_type.hpp` (new); `src/pipeline/pipeline.cpp`, `src/capture/link_type.cpp` (new); the three detectors, `detection_engine`, `rule_parser`, `signature_matcher`, `ip_utils`, the TCP/IPv4/DNS parsers, both capture classes, `main.cpp`, `packet.hpp`; `rules/default.rules`; `tests/` (5 new files, 7 extended); `bench/`; `.github/workflows/ci.yml`; `CMakeLists.txt`; `samples/*.pcap`; `tools/generate_samples.cpp`; README, `docs/`, CONTRIBUTING, Doxyfile, AGENT.md, CHANGELOG.md
- **Verification:** local build and `ctest` 130/130 (30 before); 38 of the new tests were run against the unmodified sources first and failed there; clang-format 17 clean; the suite also passes under AddressSanitizer and UBSan with `-Wall -Wextra -Wpedantic` clean, and 2.8 million mutated frames through `process_packet` under the sanitizers found nothing (a throwaway harness, not committed); sample pcaps give the same alerts as before except `syn_flood.pcap` now raises one SYN-flood alert instead of five
- **Follow-ups:** an ICMP flood detector if wanted; configurable port-scan thresholds; VLAN and IPv6 framing; DNS over TCP; fuzzing and a sanitizer job in CI; SECURITY.md still lists only 1.0.x as supported (the support policy is the owner's call)

Raouf:
- **Date:** 2026-11-17 (AEDT)
- **Scope:** Signature matching bug; README known limitations
- **Summary:** A rule with a `content:` option matched any packet that carried no payload, because the content check was skipped when the payload was empty. A rule such as `content:"GET /admin"` on port 80 therefore alerted on every bare SYN to that port. The check now fails for payload-less packets and compares through a `string_view` without copying. The README gains a "Known Limitations" section from a review of the detection code: thresholds fixed in code and rule options not applied, per-source state never evicted, an approximate port-scan window, simplified framing, minimal DNS parsing, and no end-to-end test.
- **Files changed:** `src/detection/signature_matcher.cpp`, `tests/test_signature_matcher.cpp`, `README.md`, `CHANGELOG.md`, `AGENT.md`
- **Verification:** three new tests (content rule with no payload, with a matching payload, with another payload); local build and `ctest` 30/30; clang-format 17 clean
- **Follow-ups:** wire rule thresholds through to the detectors; evict idle per-source state; an end-to-end benchmark and test through `DetectionEngine`

Raouf:
- **Date:** 2026-11-17 (AEDT)
- **Scope:** Parser field reads; README accuracy
- **Summary:** Every parser read 16- and 32-bit header fields by casting the packet pointer (`*reinterpret_cast<const uint16_t*>(data + n)`), which is an unaligned load and a strict-aliasing violation. They now go through `read_be16` / `read_be32` in `include/sentinelflow/utils/byte_order.hpp`, which copy the bytes out. The README claimed "zero-copy header extraction", which was not true, and quoted the parsing benchmark without saying that it covers header parsing of one fixed packet only; both are corrected.
- **Files changed:** `include/sentinelflow/utils/byte_order.hpp` (new), `src/parser/*.cpp`, `README.md`, `CHANGELOG.md`, `AGENT.md`
- **Verification:** local build and `ctest` 27/27; `clang-format-17 --dry-run --Werror` clean; CI on the pull request
- **Follow-ups:** add an end-to-end benchmark that runs the detection engine over a pcap

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

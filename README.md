# SentinelFlow

**Real-time network intrusion detection system built in modern C++17.**

![CI](https://github.com/Raoof128/SentinelFlow/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)

SentinelFlow captures live network traffic or replays pcap files, parses protocol headers across multiple layers (Ethernet/IPv4/TCP/UDP/ICMP/DNS/ARP), detects known attack signatures and anomalous patterns, and logs structured security alerts to the console and CSV files.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Sample Output](#sample-output)
- [Detection Capabilities](#detection-capabilities)
- [Rules Format](#rules-format)
- [Performance](#performance)
- [Known Limitations](#known-limitations)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Features

**Capture**
- Live network capture via libpcap with configurable BPF filters
- Offline `.pcap` file replay for forensic analysis

**Parsing**
- Layered protocol dissection: Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP
- Bounds-checked header parsing into plain structs, with alignment-safe field reads

**Detection**
- Snort-inspired rule engine with signature matching on protocol, address (single IP or CIDR), port, TCP flags and payload content
- Stateful detection: port scans, SYN floods, DNS tunnelling. The SYN-flood threshold and window and the DNS name length come from the rules file
- Per-source state is bounded: idle entries expire with their window and the number of tracked sources is capped

**Alerting**
- Colour-coded console output with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- CSV log export for integration with SIEM tools

**Performance**
- Header parsing benchmarked on a single thread (see [Performance](#performance) for what the figure does and does not cover)

---

## Architecture

```
                        +------------------+
                        |   Raw Packets    |
                        | (NIC / .pcap)    |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        | Capture Engine   |
                        | (libpcap)        |
                        +--------+---------+
                                 |
                                 v
                        +------------------+
                        | Parser Pipeline  |
                        | L2: Ethernet     |
                        | L3: IPv4 / ARP   |
                        | L4: TCP/UDP/ICMP |
                        | L7: DNS          |
                        +--------+---------+
                                 |
                    +------------+------------+
                    |                         |
                    v                         v
          +-----------------+      +--------------------+
          | Signature       |      | Stateful           |
          | Matcher         |      | Detectors          |
          | (rule engine)   |      | (scan/flood/tunnel)|
          +--------+--------+      +---------+----------+
                    |                         |
                    +------------+------------+
                                 |
                                 v
                        +------------------+
                        | Alert Manager    |
                        | - Console (colour)|
                        | - CSV log file   |
                        +------------------+
```

**Pipeline flow:** Raw packets are ingested by the Capture Engine (live via libpcap or from `.pcap` files). Each packet passes through the Parser Pipeline, which dissects headers layer by layer. Parsed packets are then evaluated by both the Signature Matcher (rule-based) and Stateful Detectors (port scan, SYN flood, DNS tunnel). Any matches are forwarded to the Alert Manager, which outputs colour-coded alerts to the console and optionally writes them to a CSV log.

---

## Quick Start

### Prerequisites

- **CMake** 3.18 or later
- **C++17** compatible compiler (GCC 8+ or Clang 7+)
- **libpcap** development headers (`libpcap-dev` on Debian/Ubuntu, `libpcap` via Homebrew on macOS)

### Build from source

```bash
git clone https://github.com/Raoof128/SentinelFlow.git
cd SentinelFlow
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Usage examples

```bash
# Live capture on a network interface (requires root/sudo)
sudo ./build/sentinelflow eth0

# Replay a pcap file for offline analysis
./build/sentinelflow --pcap samples/port_scan.pcap

# Load custom detection rules
sudo ./build/sentinelflow --rules rules/default.rules eth0

# Enable CSV alert logging
sudo ./build/sentinelflow --log alerts.csv eth0

# Apply a BPF filter to narrow capture scope
sudo ./build/sentinelflow --filter "tcp port 80" eth0

# Verbose mode for detailed packet output
sudo ./build/sentinelflow --verbose eth0
```

Captures must use the Ethernet link type; other link types (loopback, raw IP, 802.11) are refused with an error. `rules/default.rules` is read from the working directory unless `--rules` says otherwise, so run the binary from the repository root or pass the path. Malformed rule lines are skipped with a warning that names the line, and a count is printed when the rules are loaded.

The pcap files in `samples/` come from `tools/generate_samples.cpp` (CMake target `generate_samples`; run `./build/generate_samples` from the repository root to rewrite them).

---

## Sample Output

Real output from `./build/sentinelflow --pcap samples/port_scan.pcap` and `--pcap samples/syn_flood.pcap` with the default rules (alerts only; colour codes removed). Timestamps come from the capture file and are printed in the machine's local time zone; this run used `TZ=UTC`.

```
[HIGH] [SID:5001] 2026-03-21 00:00:01.000 10.0.1.1 -> 192.168.1.100 | Port scan detected: 15 unique ports probed in 60s
[MEDIUM] [SID:1001] 2026-03-21 00:00:02.000 10.0.1.1:40022 -> 192.168.1.100:22 | SSH connection attempt
[CRITICAL] [SID:5002] 2026-03-21 00:00:00.000 10.0.0.100 -> 192.168.1.100 | SYN flood detected: 100 SYN packets in 10s
```

---

## Detection Capabilities

| Detection | Method | Severity | Description |
|-----------|--------|----------|-------------|
| Port Scan | Stateful | HIGH | Alerts when one source sends SYNs to 15 distinct ports on one destination within 60 s. Only ports whose latest SYN is inside the window count. The 15 and 60 are built-in constants; there is no rule for them |
| SYN Flood | Stateful | CRITICAL | Counts SYNs per destination IP, from any sources, and alerts at the rule's `threshold:count,seconds` (default rules: 100 in 10 s). One alert per destination per window while a flood continues |
| DNS Tunnel | Stateful | HIGH | Counts DNS queries (not responses) whose name is longer than the rule's `dns_query_len:>N` (default rules: 50 characters); alerts at 20 such queries from one source within 60 s |
| Signature Match | Rule-based | MEDIUM | Snort-inspired rules with protocol, address (IP or CIDR), port, flag and content matching, applied to each packet on its own |

ICMP flood detection is not implemented.

---

## Rules Format

SentinelFlow uses a Snort-inspired rule syntax. Each rule specifies a protocol, source/destination addresses and ports, and one or more options:

```
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;)
alert tcp any any -> any any (flags:S; threshold:100,10; msg:"Possible SYN flood"; sid:2001;)
alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;)
alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 3306 (msg:"MySQL from the internal range"; sid:1007;)
```

The SYN-flood and DNS-tunnel rules do not match packets one by one: their values configure those two detectors when the rules are loaded. A `threshold` rule that no detector can use is reported as a warning.

See [docs/rules_format.md](docs/rules_format.md) for the full syntax reference.

---

## Performance

There are two benchmarks, and they measure different things.

**`benchmark_throughput`** parses one fixed 54-byte TCP packet 5,000,000 times on a single thread: Ethernet, IPv4 and TCP header parsing only. It does not exercise capture, DNS parsing, the rule engine or the stateful detectors, so its figure is an upper bound on parser speed and not an end-to-end detection rate. CI prints its own on every run.

**`benchmark_pipeline`** replays 10,000,000 synthetic Ethernet frames through the library pipeline (framing, parsing, statistics, the default rules, the three stateful detectors, alert dispatch) on a single thread. The frames are a fixed pseudo-random mix built in memory: about 45% TCP data, 15% bare ACKs, 15% SYNs from a large pool of sources, 10% DNS (some long names, some responses), 6% ICMP, 6% other UDP, 2% ARP and 1% fragments. Alerts go to a counter, not to the console or a file.

Result on the author's machine (Apple M2, macOS, Apple clang 21, Release build, one thread, synthetic traffic; three consecutive runs gave 8.28 to 8.30 million packets/sec):

| Metric | Value |
|--------|-------|
| Packets processed | 10,000,000 |
| Throughput | about 8,300,000 packets/sec |
| Avg latency | 0.12 us/packet |

This is a measure of the pipeline code on synthetic traffic, in memory. It leaves out libpcap, the network card, disk and console I/O, and real traffic differs from this mix, so it is a yardstick for comparing changes and not a statement of capacity. The CI job prints the same benchmark from a shared runner on every Release g++ build, which will give a different number.

Run them yourself:

```bash
cmake -B build -DBUILD_BENCH=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/bench/benchmark_throughput
./build/bench/benchmark_pipeline          # optional arguments: rules-file packet-count
```

---

## Known Limitations

SentinelFlow is a study project, written to learn how an intrusion detection pipeline fits together. A review in November 2026 listed what it did not do; the items below are what is still true after those fixes. Nothing here should be read as production-ready.

- **Port-scan thresholds are constants.** The port-scan detector always uses 15 ports in 60 s; no rule syntax configures it. Each stateful detector (SYN flood, DNS tunnel) takes its values from the first matching rule; a second rule for the same detector is ignored with a warning, and the address and port fields of those rules are not used (the detectors look at all traffic).
- **ICMP flood is not detected.** There is no ICMP detector, so a `threshold` rule on ICMP is reported as having no effect; the default rules do not contain one.
- **Tracked state is capped, not unlimited.** Each detector tracks at most 65,536 sources (or source and destination pairs) and drops the least recently active one when full, so an attacker who sends from more than 65,536 distinct sources inside a window can push other sources' state out and reset their counts.
- **Framing is partial.** Only Ethernet captures are accepted. VLAN tags are not handled (a tagged frame is counted but not parsed), IPv6 is not parsed, and fragments and TCP streams are not reassembled: a content rule sees one packet's payload at a time, and only the first fragment's transport header is read.
- **DNS parsing is minimal.** Only the first question of a UDP message is read, DNS over TCP is not parsed, and a compression pointer in the name ends the name instead of being followed.
- **Rules.** The `action` field is ignored (every matching rule alerts), and port ranges, negation and address lists are not supported. Rules with options the parser does not know are rejected.
- **Tests and benchmarks.** The tests include one end-to-end test from raw frames to alerts, but there is no fuzzing in the repository and CI does not run the tests under sanitizers. The benchmark figures are from synthetic traffic (see [Performance](#performance)).

## Testing

SentinelFlow includes 130 tests covering the parsers, rule parsing and signature matching, the three stateful detectors and their state limits, the pcap link-type check, and the pipeline end to end: raw Ethernet frames are built in memory, run through the library pipeline with a small rule set, and the alerts are asserted.

```bash
cmake -B build -DBUILD_TESTING=ON
cmake --build build -j$(nproc)
cd build && ctest --output-on-failure
```

---

## Project Structure

```
SentinelFlow/
├── CMakeLists.txt          # Top-level build configuration
├── include/sentinelflow/   # Public header files
├── src/
│   ├── main.cpp            # Entry point
│   ├── capture/            # Packet capture engine (libpcap)
│   ├── parser/             # Protocol parsers (Ethernet, IP, TCP, UDP, DNS, ARP)
│   ├── detection/          # Rule parser, signature matcher and stateful detectors
│   ├── pipeline/           # Framing and the per-packet pipeline (parse, stats, detect, alert)
│   ├── alert/              # Alert manager (console + CSV output)
│   ├── stats/              # Traffic statistics
│   └── utils/              # Shared utilities
├── tests/                  # Google Test unit and integration tests
├── bench/                  # Parser and end-to-end pipeline benchmarks
├── rules/                  # Default detection rules
├── samples/                # Sample pcap files for testing
├── docs/                   # Architecture and rules documentation
├── tools/                  # Helper utilities (sample pcap generator, CMake target generate_samples)
├── CONTRIBUTING.md         # Contribution guidelines
├── CHANGELOG.md            # Version history
└── LICENSE                 # MIT License
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on code style, commit messages, and the pull request process.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [libpcap](https://www.tcpdump.org/) -- packet capture library
- [Google Test](https://github.com/google/googletest) -- C++ testing framework
- [Snort](https://www.snort.org/) -- inspiration for the rule format syntax

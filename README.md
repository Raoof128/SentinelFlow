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
- Zero-copy header extraction for minimal overhead

**Detection**
- Snort-inspired configurable rule engine with signature matching
- Stateful detection: port scans, SYN floods, DNS tunnelling
- Threshold-based anomaly triggers with configurable time windows

**Alerting**
- Colour-coded console output with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- CSV log export for integration with SIEM tools

**Performance**
- 28M+ packets/second parsing throughput (benchmarked)
- Sub-microsecond per-packet processing latency

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

- **CMake** 3.16 or later
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

---

## Sample Output

```
[HIGH]     [SID:5001] 2024-03-21 16:46:41.000 10.0.1.1 -> 192.168.1.100 | Port scan detected: 15 unique ports probed in 60s
[MEDIUM]   [SID:1001] 2024-03-21 16:46:42.000 10.0.1.1:40022 -> 192.168.1.100:22 | SSH connection attempt
[CRITICAL] [SID:5002] 2024-03-21 16:46:50.000 10.0.1.1 -> 192.168.1.100 | SYN flood detected: 100 SYN packets in 10s
```

---

## Detection Capabilities

| Detection | Method | Severity | Description |
|-----------|--------|----------|-------------|
| Port Scan | Stateful | HIGH | Tracks unique destination ports per source-dest pair over a sliding time window |
| SYN Flood | Stateful | CRITICAL | Monitors SYN packet rate per target IP and triggers on threshold breach |
| DNS Tunnel | Stateful | HIGH | Detects unusually long DNS queries arriving at high volume |
| Signature Match | Rule-based | MEDIUM | Snort-inspired configurable rules with protocol, port, and flag matching |

---

## Rules Format

SentinelFlow uses a Snort-inspired rule syntax. Each rule specifies a protocol, source/destination addresses and ports, and one or more options:

```
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;)
alert tcp any any -> any any (flags:S; threshold:20,60; msg:"Possible SYN flood"; sid:2001;)
alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;)
```

See [docs/rules_format.md](docs/rules_format.md) for the full syntax reference.

---

## Performance

Benchmark results from `benchmark_throughput` (single-threaded, synthetic packets):

| Metric | Value |
|--------|-------|
| Packets processed | 5,000,000 |
| Throughput | 28,409,090 packets/sec |
| Avg latency | 0.035 us/packet |

Run the benchmark yourself:

```bash
cmake -B build -DBUILD_BENCH=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/bench/benchmark_throughput
```

---

## Testing

SentinelFlow includes 27 unit and integration tests covering parsers, detectors, rule parsing, and end-to-end packet processing.

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
│   ├── detection/          # Signature matcher and stateful detectors
│   ├── alert/              # Alert manager (console + CSV output)
│   ├── stats/              # Traffic statistics
│   └── utils/              # Shared utilities
├── tests/                  # Google Test unit and integration tests
├── bench/                  # Throughput benchmark
├── rules/                  # Default detection rules
├── samples/                # Sample pcap files for testing
├── docs/                   # Architecture and rules documentation
├── tools/                  # Helper utilities (sample generator)
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

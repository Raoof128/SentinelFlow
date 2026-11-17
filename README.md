# SentinelFlow

**A network intrusion detection system in C++17. A study project, not a production tool: see [Known Limitations](#known-limitations).**

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
- CSV alert log

**Performance**
- Two single-thread benchmarks on synthetic traffic: header parsing alone, and the whole pipeline end to end (see [Performance](#performance) for what each figure does and does not cover)

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
- A **C++17** compiler. CI builds with GCC 15 and Clang 21 on Ubuntu; it also builds with Apple clang 21 on macOS. Older compilers have not been tried
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
| DNS Tunnel | Stateful | HIGH | Counts DNS messages sent to port 53 (whatever their QR bit says; messages from port 53 to another port are replies and are ignored) whose name is longer than the rule's `dns_query_len:>N` (default rules: 50 characters); alerts at 20 such queries from one source within 60 s |
| Signature Match | Rule-based | MEDIUM | Snort-inspired rules with protocol, address (IP or CIDR), port, flag and content matching, applied to each packet on its own |

ICMP flood detection is not implemented. When a detector's state table is full and has to drop live records, the engine raises a MEDIUM "State table pressure" alert (SID 5100, at most one per minute) and the end-of-run summary reports the count, so the operator can see detection is degraded.

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

This is a measure of the pipeline code on synthetic traffic, in memory. It leaves out libpcap, the network card, disk and console I/O, and real traffic differs from this mix, so it is a yardstick for comparing changes and not a statement of capacity. The CI job prints the same benchmark on every Release g++ build, on a shared GitHub-hosted runner. The five runs made while this benchmark was being added (17 November 2026, GCC 15) printed 4,250,673, 4,594,734, 4,758,394, 7,742,303 and 7,779,522 packets/sec, so shared-runner figures vary by almost a factor of two between runs of near-identical code. Treat any single number, including the one above, as indicative.

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
- **Tracked state is capped, and a cap can be attacked.** Each detector tracks at most 65,536 sources (or source and destination pairs). Records that have expired are dropped first. When the table is full of live records, the victim is the least advanced towards its alert threshold among the eight least recently active, so a source close to triggering outlives the single-packet records used to flush the table. That is a heuristic: an attacker who can spoof enough distinct sources can still fill the table, and one who makes more than eight records as advanced as the target can still push it out and reset its count. A bounded table cannot prevent this; it makes it expensive and visible, through the capacity-eviction counters, the SID 5100 alert and the end-of-run warning.
- **Framing is partial.** Only Ethernet captures are accepted. VLAN tags are not handled (a tagged frame is counted but not parsed), IPv6 is not parsed, and fragments and TCP streams are not reassembled: a content rule sees one packet's payload at a time, and only the first fragment's transport header is read.
- **DNS parsing is minimal.** Only the first question of a UDP message is read, DNS over TCP is not parsed, and a compression pointer in the name ends the name instead of being followed.
- **Rules.** The `action` field is ignored (every matching rule alerts), and port ranges, negation and address lists are not supported. Rules with options the parser does not know are rejected.
- **Packet time is trusted.** The stateful detectors take time from the capture's timestamps and never let it run backwards. One packet stamped far in the future (a corrupt or crafted capture file) therefore becomes "now" for everything after it: windows stop sliding, so counts build up across the rest of the run and the port-scan detector can alert on ports that were probed hours apart.
- **Tests and benchmarks.** The tests include end-to-end tests from raw frames to alerts, and CI runs the suite and replays the sample captures under AddressSanitizer and UndefinedBehaviorSanitizer, but there is no fuzzing in the repository. The benchmark figures are from synthetic traffic (see [Performance](#performance)).

## Testing

SentinelFlow includes 147 tests covering the parsers, rule parsing and signature matching, the three stateful detectors and their state limits, the pcap link-type check, and the pipeline end to end: raw Ethernet frames are built in memory, run through the library pipeline with a small rule set, and the alerts are asserted.

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

# SentinelFlow

Real-time network intrusion detection system built in C++17.

Captures live network traffic, parses protocol headers (Ethernet/IPv4/TCP/UDP/ICMP/DNS/ARP),
detects known attack signatures, and logs structured security alerts.

## Features

- **Packet capture:** Live capture via libpcap or offline .pcap replay
- **Protocol parsing:** Ethernet, IPv4, TCP, UDP, ICMP, DNS, ARP
- **Signature detection:** Configurable rule engine (Snort-inspired format)
- **Stateful detection:** Port scans, SYN floods, DNS tunnelling
- **Alerting:** Coloured console output + CSV log export
- **Performance:** 500K+ packets/second parsing throughput (benchmarked)

## Quick Start

```bash
# Live capture (requires sudo for raw sockets)
sudo ./sentinelflow en0

# Offline .pcap replay
./sentinelflow --pcap samples/port_scan.pcap

# Custom rules + CSV logging
sudo ./sentinelflow --rules rules/custom.rules --log alerts.csv en0

# BPF filter
sudo ./sentinelflow --filter "tcp port 80" en0
```

## Build

```bash
cmake -B build
cmake --build build
```

## Run Tests

```bash
cmake -B build -DBUILD_TESTING=ON
cmake --build build
cd build && ctest --output-on-failure
```

## Run Benchmark

```bash
cmake -B build -DBUILD_BENCH=ON
cmake --build build
./build/bench/benchmark_throughput
```

## Architecture

```
Raw Packets -> Capture Engine -> Parser Pipeline -> Detection Engine -> Alert Manager
```

- **Capture Engine:** Live network capture (libpcap) or .pcap file replay
- **Parser Pipeline:** Layered protocol dissection (L2-L7)
- **Detection Engine:** Signature matching + stateful analysis (port scans, SYN floods, DNS tunnelling)
- **Alert Manager:** Pluggable outputs (console, CSV)

See [docs/architecture.md](docs/architecture.md) for details.

## Detection Rules

Snort-inspired rule format:

```
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;)
alert tcp any any -> any any (flags:S; threshold:20,60; msg:"Possible SYN flood"; sid:2001;)
alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;)
```

See [docs/rules_format.md](docs/rules_format.md) for full syntax.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | C++17 |
| Build | CMake |
| Testing | Google Test |
| Packet capture | libpcap |
| CI/CD | GitHub Actions |

## License

MIT License - see [LICENSE](LICENSE)

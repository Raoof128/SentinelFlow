# SentinelFlow Architecture

## Overview

SentinelFlow is a real-time network intrusion detection system (NIDS) built in C++17.

## Pipeline

```
Raw Packets → Capture Engine → Parser Pipeline → Detection Engine → Alert Manager
```

### Capture Engine
- **LiveCapture**: Captures packets from a network interface using libpcap in promiscuous mode
- **PcapFileReader**: Replays packets from .pcap files for offline analysis

### Parser Pipeline
Layered protocol parsing:
1. **Ethernet** (Layer 2) - MAC addresses, EtherType
2. **IPv4** (Layer 3) - IP addresses, TTL, protocol
3. **TCP/UDP/ICMP** (Layer 4) - Ports, flags, payload
4. **DNS** (Layer 7) - Query names, types
5. **ARP** (Layer 2.5) - Address resolution

### Detection Engine
Three detection strategies:
1. **Signature Matching** - Rule-based pattern matching (Snort-inspired format)
2. **Stateful Analysis** - Port scan detection, SYN flood detection
3. **Protocol Anomaly** - DNS tunnelling detection via query length analysis

### Alert Manager
Pluggable output system:
- **ConsoleLogger** - Colour-coded terminal output
- **CsvLogger** - Structured CSV file logging

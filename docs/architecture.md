# SentinelFlow Architecture

## Overview

SentinelFlow is a real-time network intrusion detection system (NIDS) built in C++17. It captures network traffic (live or from pcap files), parses protocol headers at multiple layers, runs detection logic against parsed packets, and emits alerts through a pluggable output system.

## High-Level Pipeline

```
Raw Packets --> Capture Engine --> Parser Pipeline --> Detection Engine --> Alert Manager
                  (libpcap)        (Layer 2-7)       (rules + state)      (console/CSV)
```

## Components

### Capture Engine

The capture layer provides a uniform `PacketCapture` interface with two implementations:

- **LiveCapture** (`src/capture/live_capture.cpp`): Captures packets from a network interface using libpcap in promiscuous mode. Supports BPF filter expressions (e.g., `tcp port 80`). Requires root/sudo privileges.
- **PcapFileReader** (`src/capture/pcap_file_reader.cpp`): Replays packets from `.pcap` files for offline analysis and testing. Uses the same callback-based interface as LiveCapture.

Both implementations deliver packets to the processing callback as raw byte buffers with timestamps.

### Parser Pipeline

Layered protocol parsing, each parser is stateless and operates on a byte buffer:

1. **Ethernet** (Layer 2) - Extracts source/destination MAC addresses and EtherType. Entry point for all packets.
2. **ARP** (Layer 2.5) - Parses address resolution protocol fields (sender/target MAC and IP, opcode).
3. **IPv4** (Layer 3) - Extracts IP addresses, TTL, protocol number, IHL, and other header fields.
4. **TCP** (Layer 4) - Extracts ports, sequence/ack numbers, flags (SYN/ACK/FIN/RST/PSH/URG), window size.
5. **UDP** (Layer 4) - Extracts ports, length, and checksum.
6. **ICMP** (Layer 4) - Extracts type, code, identifier, and sequence number.
7. **DNS** (Layer 7) - Extracts transaction ID, flags, query name, and query type. Triggered when UDP source or destination port is 53.

Each parser returns a boolean indicating success. On failure the corresponding `std::optional` field in `ParsedPacket` remains empty, and subsequent layers are skipped gracefully.

### Detection Engine

The detection engine (`src/detection/detection_engine.cpp`) applies multiple detection strategies to each parsed packet:

1. **Signature Matching** (rule-based): Loads rules from a Snort-inspired rule file. Matches on protocol, IP addresses, ports, TCP flags, payload content, and DNS query length. See `docs/rules_format.md`.
2. **Port Scan Detector** (stateful): Tracks the number of distinct destination ports contacted by each source IP within a sliding time window. Fires alert SID 5001 when the threshold is exceeded.
3. **SYN Flood Detector** (stateful): Tracks SYN packets per destination IP. Fires when the SYN rate exceeds a configured threshold within the time window.
4. **DNS Tunnelling Detector** (protocol anomaly): Flags DNS queries with unusually long domain names, which may indicate data exfiltration via DNS tunnelling.

The engine returns a `std::vector<Alert>` for each packet. Alerts carry source/destination IPs and ports, a severity level, a human-readable message, and a signature ID (SID).

### Alert Manager

The alert manager (`src/alert/alert_manager.cpp`) dispatches alerts to one or more pluggable output backends:

- **ConsoleLogger** (`src/alert/console_logger.cpp`): Colour-coded terminal output with timestamp, severity, SID, and message.
- **CsvLogger** (`src/alert/csv_logger.cpp`): Appends alerts to a CSV file with columns: timestamp, severity, sid, src_ip, src_port, dst_ip, dst_port, message. Properly escapes embedded quotes in messages per RFC 4180.

New output backends can be added by implementing the `AlertOutput` interface (see "Extending the System" below).

### Traffic Statistics

The `TrafficStats` module (`src/stats/traffic_stats.cpp`) records per-protocol packet and byte counts. A summary is printed when the capture session ends (on Ctrl+C or end of pcap file).

## Data Flow: Life of a Packet

1. **Capture**: libpcap delivers a raw Ethernet frame as a `const uint8_t*` buffer with a timestamp.
2. **Ethernet parsing**: `parse_ethernet()` extracts the EtherType. If `0x0800` (IPv4), proceed to IP parsing. If `0x0806` (ARP), parse ARP.
3. **IP parsing**: `parse_ipv4()` extracts the protocol field. Based on protocol number:
   - `6` (TCP): parse TCP header, then extract payload pointer and length.
   - `17` (UDP): parse UDP header. If port 53, also parse DNS.
   - `1` (ICMP): parse ICMP header.
4. **Statistics**: `TrafficStats::record()` counts the packet by protocol and accumulates byte totals.
5. **Verbose output** (if `-v` flag): Print a one-line summary to stdout (source, destination, protocol, flags, length).
6. **Detection**: `DetectionEngine::analyze()` runs the packet through all signature rules and stateful detectors. Returns a vector of alerts (may be empty).
7. **Alerting**: If alerts were generated, `AlertManager::process()` dispatches each alert to all registered output backends (console, CSV file).

## Detection Strategies

### Signature-Based Detection

Rules are loaded from text files in a Snort-like format. Each rule specifies:
- A header filter (action, protocol, source/destination IP and port)
- Options: message, SID, TCP flags, content pattern, threshold, DNS query length

The signature matcher iterates over all loaded rules for each packet. A rule matches when all of its specified conditions are satisfied. This is a straightforward linear scan; for deployments with very large rule sets, indexing by protocol/port would improve performance.

### Stateful Detection

Stateful detectors maintain internal data structures (typically `std::unordered_map` keyed by IP address) that track activity over time:

- **Port scan detection**: A map from source IP to a set of destination ports contacted, with a timestamp window. When the set size exceeds the threshold within the window, an alert fires and the entry resets.
- **SYN flood detection**: A map from destination IP to SYN packet count with a timestamp window. Exceeding the threshold triggers an alert.

State entries are lazily cleaned up: when the time window expires, the entry is reset on the next packet from that IP.

### Protocol Anomaly Detection

Currently limited to DNS tunnelling detection based on query name length. This is configured via the `dns_query_len:>N` rule option. Queries with names longer than N characters are flagged.

## Threading Model

SentinelFlow currently operates on a **single thread**. The libpcap callback, protocol parsing, detection, and alerting all execute synchronously in the packet processing loop. This simplifies the architecture and avoids synchronization overhead.

For higher-throughput deployments, potential parallelism strategies include:
- A producer-consumer model with a lock-free ring buffer between capture and processing.
- Per-flow parallel processing (packets belonging to the same flow are always handled by the same thread to preserve stateful detector correctness).
- Separate threads for alert I/O to avoid blocking the packet processing path.

## Extending the System

### Adding a New Protocol Parser

1. Create a header struct in `include/sentinelflow/parser/packet.hpp` (e.g., `HTTPHeader`).
2. Add a `std::optional<HTTPHeader>` field to `ParsedPacket`.
3. Implement `parse_http()` in `src/parser/http_parser.cpp` with a corresponding header in `include/sentinelflow/parser/http_parser.hpp`.
4. Call the parser from `process_packet()` in `src/main.cpp` at the appropriate layer (e.g., when TCP port is 80/443).
5. Update `Protocol` enum and `highest_protocol()` if relevant.

### Adding a New Detector

1. Create a new class (e.g., `HttpAnomalyDetector`) implementing the detector interface.
2. Register it in `DetectionEngine`'s constructor or initialization.
3. The detector receives `const ParsedPacket&` and returns `std::vector<Alert>`.
4. Assign a unique SID range for the new detector's alerts.

### Adding a New Alert Output

1. Implement the `AlertOutput` interface (the `emit(const Alert&)` method).
2. Register an instance with `AlertManager::add_output()` in `main.cpp`.
3. Examples of additional outputs: syslog, JSON file, webhook/HTTP POST, UNIX socket.

## Directory Structure

```
SentinelFlow/
  include/sentinelflow/     # Public headers
    parser/                 # Protocol parsers and ParsedPacket
    detection/              # Detection engine, rule parser, detectors
    capture/                # Capture interfaces
    alert/                  # Alert types and output interfaces
    stats/                  # Traffic statistics
    utils/                  # IP utilities, timestamp formatting, types
  src/                      # Implementation files (mirrors include/ layout)
  tests/                    # Google Test unit and integration tests
  rules/                    # Default detection rule files
  docs/                     # Documentation
  tools/                    # Auxiliary scripts and utilities
```

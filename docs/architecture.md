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

Both implementations deliver packets to the processing callback as raw byte buffers with timestamps. Both refuse a source whose link type is not Ethernet (`DLT_EN10MB`) with an error naming the link type found (`src/capture/link_type.cpp`), because the parsers only understand Ethernet framing.

### Parser Pipeline

Layered protocol parsing, each parser is stateless and operates on a byte buffer:

1. **Ethernet** (Layer 2) - Extracts source/destination MAC addresses and EtherType. Entry point for all packets.
2. **ARP** (Layer 2.5) - Parses address resolution protocol fields (sender/target MAC and IP, opcode).
3. **IPv4** (Layer 3) - Extracts IP addresses, TTL, protocol number, IHL, and other header fields.
4. **TCP** (Layer 4) - Extracts ports, sequence/ack numbers, flags (SYN/ACK/FIN/RST/PSH/URG), window size.
5. **UDP** (Layer 4) - Extracts ports, length, and checksum.
6. **ICMP** (Layer 4) - Extracts type, code, identifier, and sequence number.
7. **DNS** (Layer 7) - Extracts transaction ID, flags (including whether the message is a response), the first question's name, and query type. Triggered when UDP source or destination port is 53. A compression pointer in the name ends the name; only the first question is read.

Each parser returns a boolean indicating success. On failure the corresponding `std::optional` field in `ParsedPacket` remains empty, and subsequent layers are skipped gracefully.

The parsers read headers; the framing decisions that tie the layers together live in `parse_packet()` (`src/pipeline/pipeline.cpp`, see "Data Flow" below). The parsers themselves reject structurally impossible headers: an IPv4 IHL below 5 or longer than the buffer, a TCP data offset below 5 words or beyond the segment, a DNS label longer than 63 bytes or a name longer than 255.

### Detection Engine

The detection engine (`src/detection/detection_engine.cpp`) applies multiple detection strategies to each parsed packet:

1. **Signature Matching** (rule-based): Loads rules from a Snort-inspired rule file. Matches on protocol, IP addresses (single address or CIDR block), ports, TCP flags and payload content. See `docs/rules_format.md`.
2. **Port Scan Detector** (stateful): Tracks the distinct destination ports contacted by each source against each destination within a sliding time window (15 ports in 60 s, built-in constants). Only ports whose latest SYN is inside the window count. Fires alert SID 5001.
3. **SYN Flood Detector** (stateful): Tracks SYN packets per destination IP. Fires SID 5002 when the count within the window reaches the threshold, then at most once per window per destination. Threshold and window come from the SYN-flood rule (built-in default 100 in 10 s).
4. **DNS Tunnelling Detector** (protocol anomaly): Counts DNS messages with unusually long names. A message is a reply, and ignored, only if the transport says so (sent from port 53 to another port); the DNS QR bit is the sender's to set, so a message sent to port 53 is analysed whatever it claims, which may indicate data exfiltration via DNS tunnelling. Fires SID 5003. The name length comes from the `dns_query_len` rule (default 50); volume and window default to 20 in 60 s.

`DetectionEngine::apply_rules()` hands the rule values to the SYN-flood and DNS-tunnel detectors when rules are loaded. A rule that cannot take effect (for example a `threshold` rule for ICMP, which has no detector) is reported as a warning. The engine returns a `std::vector<Alert>` for each packet. Alerts carry source/destination IPs and ports, a severity level, a human-readable message, and a signature ID (SID).

### Alert Manager

The alert manager (`src/alert/alert_manager.cpp`) dispatches alerts to one or more pluggable output backends:

- **ConsoleLogger** (`src/alert/console_logger.cpp`): Colour-coded terminal output with timestamp, severity, SID, and message.
- **CsvLogger** (`src/alert/csv_logger.cpp`): Appends alerts to a CSV file with columns: timestamp, severity, sid, src_ip, src_port, dst_ip, dst_port, message. Properly escapes embedded quotes in messages per RFC 4180.

New output backends can be added by implementing the `AlertOutput` interface (see "Extending the System" below).

### Traffic Statistics

The `TrafficStats` module (`src/stats/traffic_stats.cpp`) records per-protocol packet and byte counts. A summary is printed when the capture session ends (on Ctrl+C or end of pcap file).

## Data Flow: Life of a Packet

1. **Capture**: libpcap delivers a raw Ethernet frame as a `const uint8_t*` buffer with a timestamp.
2. **Ethernet parsing**: `parse_ethernet()` extracts the EtherType. If `0x0800` (IPv4), proceed to IP parsing. If `0x0806` (ARP), parse ARP. Anything else (VLAN-tagged frames, IPv6) is counted but not parsed.
3. **IP parsing and framing**: `parse_ipv4()` extracts the header. The IP packet is then trimmed to the header's total length, so Ethernet padding is never read as payload (a total length of 0 means "use what was captured"; a length shorter than the header makes the IP layer invalid; a length beyond the captured bytes is clamped). A non-first fragment (non-zero fragment offset) has no transport header and stops here. Otherwise, based on protocol number:
   - `6` (TCP): parse TCP header (rejected if the data offset is below 5 or beyond the segment), then extract payload pointer and length.
   - `17` (UDP): parse UDP header (rejected if its length is below 8), trim the payload to the UDP length. If port 53, also parse DNS.
   - `1` (ICMP): parse ICMP header.
4. **Statistics**: `TrafficStats::record()` counts the packet by protocol and accumulates byte totals.
5. **Verbose output** (if `-v` flag): Print a one-line summary to stdout (source, destination, protocol, flags, length).
6. **Detection**: `DetectionEngine::analyze()` runs the packet through all signature rules and stateful detectors. Returns a vector of alerts (may be empty).
7. **Alerting**: If alerts were generated, `AlertManager::process()` dispatches each alert to all registered output backends (console, CSV file).

Steps 2 to 7 are `process_packet()` in `src/pipeline/pipeline.cpp` (`parse_packet()` does steps 2 and 3). `main.cpp` calls it from the capture callback, and the tests and the pipeline benchmark call it directly.

## Detection Strategies

### Signature-Based Detection

Rules are loaded from text files in a Snort-like format. Each rule specifies:
- A header filter (action, protocol, source/destination IP or CIDR block and port)
- Options: message, SID, TCP flags, content pattern, threshold, DNS query length

The signature matcher iterates over all loaded rules for each packet. A rule matches when all of its specified conditions are satisfied; a condition on an address, port or TCP flags cannot be satisfied by a packet that has no IPv4, TCP/UDP or TCP header respectively. Rules with `threshold` or `dns_query_len` are not matched per packet: their values configure the stateful detectors. This is a straightforward linear scan; for deployments with very large rule sets, indexing by protocol/port would improve performance.

### Stateful Detection

Stateful detectors keep per-key state in a `SourceTable` (`include/sentinelflow/detection/source_table.hpp`): a hash map plus a list ordering the records by last update.

- **Port scan detection**: Keyed by (source IP, destination IP). Each record holds the ports probed, each with the time of its latest SYN, oldest first; ports older than the window are dropped from the front, so only ports seen inside the window count. When the count reaches the threshold an alert fires and the record resets.
- **SYN flood detection**: Keyed by destination IP. Each record holds the newest `threshold` SYN timestamps inside the window and the time of the last alert; an alert fires when the record is full and no alert was raised in the last window.
- **DNS tunnel detection**: Keyed by source IP, with the timestamps of its long queries inside the window.

State is bounded in two ways. Records not updated within the window are evicted, examined from the cold end of the list, so each record is touched once on its way out and the cost per packet is constant on average. And each table holds at most `kDefaultMaxTrackedSources` (65,536) records. Because idle records are removed before a new one is added, a full table holds live records; to make room `SourceTable` looks at the `kEvictionCandidates` (8) least recently updated and drops the one with the least progress towards its threshold (ties: the oldest), so a source close to alerting is not the first to go when an attacker sprays single-packet sources. Constant cost per packet; but it is a heuristic, and an attacker who can spoof enough sources can still fill the table and push state out. Each table counts these capacity evictions, and `DetectionEngine::analyze()` raises a MEDIUM "State table pressure" alert (SID 5100, at most one per minute of packet time) when they occur; `main` prints the totals at the end of a run. Per-record state is O(threshold). Packet time is treated as non-decreasing (a packet stamped earlier than the newest seen is treated as arriving at the newest time), which keeps the list order valid when a capture has slightly out-of-order timestamps.

### Protocol Anomaly Detection

Currently limited to DNS tunnelling detection based on query name length. The length is configured via the `dns_query_len:>N` rule option: queries (not responses) with names longer than N characters count towards the alert threshold.

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
4. Call the parser from `parse_packet()` in `src/pipeline/pipeline.cpp` at the appropriate layer (e.g., when TCP port is 80/443).
5. Update `Protocol` enum and `highest_protocol()` if relevant.

### Adding a New Detector

1. Create a new class (e.g., `HttpAnomalyDetector`). Detectors have no common base class: each has a `check(const ParsedPacket&)` that returns `std::optional<Alert>`. Use `SourceTable` for per-source state so it is bounded.
2. Add it as a member of `DetectionEngine` and call it from `DetectionEngine::analyze()`. If a rule should configure it, read the values in `DetectionEngine::apply_rules()`.
3. Assign a unique SID range for the new detector's alerts.

### Adding a New Alert Output

1. Implement the `AlertOutput` interface (the `emit(const Alert&)` method).
2. Register an instance with `AlertManager::add_output()` in `main.cpp` (the pipeline tests register a collecting output the same way).
3. Examples of additional outputs: syslog, JSON file, webhook/HTTP POST, UNIX socket.

## Directory Structure

```
SentinelFlow/
  include/sentinelflow/     # Public headers
    parser/                 # Protocol parsers and ParsedPacket
    detection/              # Detection engine, rule parser, detectors, SourceTable
    pipeline/               # parse_packet() and process_packet()
    capture/                # Capture interfaces
    alert/                  # Alert types and output interfaces
    stats/                  # Traffic statistics
    utils/                  # IP utilities, timestamp formatting, types
  src/                      # Implementation files (mirrors include/ layout)
  bench/                    # Parser and end-to-end pipeline benchmarks
  tests/                    # Google Test unit and end-to-end tests
  rules/                    # Default detection rule files
  docs/                     # Documentation
  tools/                    # Sample pcap generator (CMake target generate_samples)
```

# SentinelFlow Rules Format

## Syntax

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

## Fields

| Field | Values | Description |
|-------|--------|-------------|
| action | any word, conventionally `alert` | Currently ignored: every rule that matches raises an alert |
| protocol | tcp, udp, icmp, any | Protocol to match |
| src_ip | `any`, an IPv4 address, or an IPv4 CIDR block | Source address filter |
| src_port | port or "any" | Source port filter |
| dst_ip | `any`, an IPv4 address, or an IPv4 CIDR block | Destination address filter |
| dst_port | port or "any" | Destination port filter |

Addresses are dotted-quad IPv4 (`192.168.1.100`) or CIDR (`10.0.0.0/8`, prefix 0 to 32; host bits in the address are ignored, so `10.1.2.3/8` is the same block as `10.0.0.0/8`). A rule that names an address needs an IPv4 packet and a rule that names a port needs a TCP or UDP packet: an ARP frame, an ICMP message or a non-first IP fragment never matches it.

## Options

Options are semicolon-separated inside parentheses:

| Option | Format | Description |
|--------|--------|-------------|
| msg | msg:"text" | Alert message |
| sid | sid:1001 | Signature ID, a non-negative integer |
| flags | flags:S | TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG); the packet must be TCP and have every listed flag set |
| threshold | threshold:count,seconds | Rate-based detection, both values at least 1. Used by the SYN-flood and DNS-tunnel detectors, see below |
| dns_query_len | dns_query_len:>50 | DNS query names longer than this many characters count as long |
| content | content:"pattern" | Payload pattern match within one packet's payload |

## Rules that configure a detector

Two kinds of rule do not match packets one at a time. When the rules are loaded their values are passed to a stateful detector, and the built-in default is used for anything no rule sets:

| Rule | Detector | What the rule sets | Built-in default |
|------|----------|--------------------|------------------|
| `tcp` rule with `flags:S` and `threshold:count,seconds` | SYN flood (SID 5002) | SYNs to one destination within the window that raise an alert | 100 in 10 s |
| any rule with `dns_query_len:>N` | DNS tunnel (SID 5003) | Name length that counts as long | 50 |
| the same rule, if it also has `threshold:count,seconds` | DNS tunnel (SID 5003) | Long queries from one source within the window | 20 in 60 s |

The port-scan detector (SID 5001) has no rule; it always uses 15 distinct ports in 60 s.

Notes on these rules:

- The detector counts all traffic. The address and port fields of the rule are not applied to it (the DNS rule's `53` is expected); a warning is printed if they would restrict anything.
- If several rules would configure the same detector, the first one in the file is used and the others produce a warning.
- A `threshold` rule that no detector consumes (for example one for ICMP) has no effect and produces a warning. **ICMP flood detection is not implemented**, so `rules/default.rules` does not contain a rule for it.
- A SYN flood raises one alert per destination per window while it continues, not one per threshold-th packet.

## Validation

A rule line that is malformed is not loaded. A warning naming the file, line number and reason is printed on stderr, and a count of rejected lines follows when loading ends. A line is rejected for:

- a missing field, a missing `->`, or no option list in parentheses
- an unknown protocol, an address that is not `any`, an IPv4 address or a CIDR block, or a port that is not `any` or a number from 0 to 65535 (ranges are not supported)
- an option the parser does not know (dropping it would silently widen the rule)
- a `sid`, `threshold` count or seconds, or `dns_query_len` that is not a plain non-negative integer (a negative sid, trailing text and overflow are all rejected), or a threshold with a zero value
- an unknown flag letter, or a `msg` or `content` value that is not in double quotes

## Examples

```
# Alert on SSH connections
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;)

# Detect SYN flood (100 SYNs to one destination in 10 seconds)
alert tcp any any -> any any (flags:S; threshold:100,10; msg:"Possible SYN flood"; sid:2001;)

# Detect DNS tunnelling (queries with names longer than 50 chars)
alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;)

# Alert on MySQL connections from the internal range to the server network
alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 3306 (msg:"Internal MySQL access"; sid:1007;)

# Detect HTTP requests containing a specific pattern
alert tcp any any -> any 80 (content:"GET /admin"; msg:"Admin page access"; sid:4001;)

# Detect Christmas tree scan (all flags set)
alert tcp any any -> any any (flags:SAFPRU; msg:"Xmas tree scan detected"; sid:4002;)
```

## Flag Reference

| Character | Flag | Hex Value |
|-----------|------|-----------|
| S | SYN | 0x02 |
| A | ACK | 0x10 |
| F | FIN | 0x01 |
| R | RST | 0x04 |
| P | PSH | 0x08 |
| U | URG | 0x20 |

Multiple flags can be combined (e.g., `flags:SA` matches packets with both SYN and ACK set; other flags may also be set).

## Notes

- Lines beginning with `#` are treated as comments and ignored, as are blank lines. A `#` comment may also follow the closing parenthesis.
- Options are separated by semicolons. A semicolon inside a quoted `msg` or `content` value is part of the value.
- The `msg` and `content` values must be enclosed in double quotes.
- The `sid` (Signature ID) should be unique across all rules.
- Port values must be numeric or the keyword `any`. Port ranges are not currently supported.

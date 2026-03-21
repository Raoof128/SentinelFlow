# SentinelFlow Rules Format

## Syntax

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

## Fields

| Field | Values | Description |
|-------|--------|-------------|
| action | alert, log | What to do on match |
| protocol | tcp, udp, icmp, any | Protocol to match |
| src_ip | IP or "any" | Source IP filter |
| src_port | port or "any" | Source port filter |
| dst_ip | IP or "any" | Destination IP filter |
| dst_port | port or "any" | Destination port filter |

## Options

Options are semicolon-separated inside parentheses:

| Option | Format | Description |
|--------|--------|-------------|
| msg | msg:"text" | Alert message |
| sid | sid:1001 | Signature ID |
| flags | flags:S | TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG) |
| threshold | threshold:count,seconds | Rate-based detection |
| dns_query_len | dns_query_len:>50 | Minimum DNS query length |
| content | content:"pattern" | Payload pattern match |

## Examples

```
# Alert on SSH connections
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;)

# Detect SYN flood (20 SYNs in 60 seconds)
alert tcp any any -> any any (flags:S; threshold:20,60; msg:"Possible SYN flood"; sid:2001;)

# Detect DNS tunnelling (queries longer than 50 chars)
alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;)

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

Multiple flags can be combined (e.g., `flags:SA` matches packets with both SYN and ACK set).

## Notes

- Lines beginning with `#` are treated as comments and ignored.
- Each option must be terminated with a semicolon (`;`).
- The `msg` and `content` values must be enclosed in double quotes.
- The `sid` (Signature ID) should be unique across all rules.
- Port values must be numeric or the keyword `any`. Port ranges are not currently supported.

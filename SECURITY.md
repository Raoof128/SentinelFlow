# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in SentinelFlow, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **raoof.abedini@proton.me**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgement:** within 48 hours
- **Assessment:** within 7 days
- **Fix or mitigation:** as soon as practical after assessment

## Scope

This policy covers vulnerabilities in the SentinelFlow tool itself, such as:

- Buffer overflows in protocol parsers
- Rule injection or parser bypass
- Crashes from malformed input (pcap files, rule files)
- Unsafe memory access

This policy does **not** cover the network attacks that SentinelFlow detects (port scans, SYN floods, etc.). Those are the threats the tool is designed to identify.

## Responsible Disclosure

We ask that you:

1. Give us reasonable time to address the issue before public disclosure
2. Avoid accessing or modifying other users' data
3. Act in good faith to avoid disruption

We will credit reporters in the changelog unless anonymity is preferred.

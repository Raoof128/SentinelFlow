# Security Policy

SentinelFlow is a study project maintained by one person in spare time. It is not hardened for production use; the README lists its known limitations.

## Supported Versions

Only the current `main` branch is maintained. There are no supported release branches.

## Reporting a Vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting instead:

**[Report a vulnerability](https://github.com/Raoof128/SentinelFlow/security/advisories/new)** (the "Report a vulnerability" button on the repository's Security tab)

Useful things to include:

- What the problem is and what an attacker gains
- Steps or an input (a pcap or rules file) that reproduce it
- A suggested fix, if you have one

Reports are read and answered as time allows; there is no guaranteed response time. Reporters are credited in the changelog unless they prefer otherwise.

## Scope

In scope are flaws in SentinelFlow itself, for example:

- Memory-safety errors in the protocol parsers
- Crashes or hangs from malformed input (pcap files, rules files)
- A way to evade a detector that the documentation says it catches

The network attacks SentinelFlow looks for (port scans, SYN floods and so on) are not vulnerabilities in it. Evasions that follow from a documented limitation (no reassembly, a bounded state table, IPv4 only) are known; a report is still welcome if it shows something the README does not already say.

# PacketDesk Changelog

All notable changes to this project will be documented in this file.

## [1.1.0.0] - 2026-06-23

### Improvements

- Enhanced TLS Inspector tool to better handle invalid certificates

---

## [1.0.1.0] - 2026-06-23

### Bug Fixes

- Fixed temp file storage issues when deployed via the Windows Store (MSIX packaging)

---

## [1.0.0.0]

### Initial Release

- Tabbed GUI with maximized window and focused Tools page
- Traceroute runner with periodic refresh
- Per-hop ping monitoring: current, min, max, average latency, packet loss, jitter, sent/received counts
- Per-hop latency distribution chart
- Bottom timeline chart with latency line and packet-loss spikes
- Configurable ping interval and traceroute refresh frequency
- Multi-tool network diagnostics panel:
  - DNS Lookup
  - DNS Propagation / Multi-DNS Resolver
  - WHOIS Lookup
  - Port Check
  - HTTP/HTTPS Check
  - TLS Inspector
  - Local Network Info
  - ARP Table Viewer
  - Route Table Viewer
  - Active Connections Viewer
  - Bandwidth / Interface Monitor
  - Subnet Calculator
  - MTU / Fragmentation Test

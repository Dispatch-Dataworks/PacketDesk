# PacketDesk

A Windows executable-ready Python GUI for route, latency, and network troubleshooting.

## What it does

- Opens maximized with a tabbed interface and a focused Tools page.
- Accepts a target domain, hostname, pasted URL, or IP address.
- Runs a traceroute before the first ping set and periodically refreshes it.
- Periodically pings every hop discovered in the route.
- Tracks current, minimum, maximum, average latency, packet loss, jitter, sent count, and received count.
- Shows a per-hop latency distribution chart.
- Shows a bottom timeline chart for the selected hop, with latency points/line and packet-loss spikes.
- Lets the user choose ping interval and how many ping sets pass before rerunning traceroute.
- Includes a multi-tool network diagnostics panel for DNS, WHOIS, port checks, HTTP/HTTPS checks, TLS inspection, local network info, ARP, route table, active connections, bandwidth monitoring, subnet calculations, DNS propagation checks, and MTU/fragmentation testing.

## Tools

- DNS Lookup
- DNS Propagation / Multi-DNS Resolver
- WHOIS Lookup
- Port Check
- HTTP Check
- TLS Inspector
- Local Network Info
- ARP Table Viewer
- Route Table Viewer
- Active Connections Viewer
- Bandwidth / Interface Monitor
- Subnet Calculator
- MTU / Fragmentation Test

## Run from source on Windows

```bat
run_windows.bat
```

## Build the Windows executable

```bat
build_windows.bat
```

The finished executable will be:

```text
dist\PacketDesk.exe
```

## Notes

- No administrator rights are required because the app shells out to the built-in Windows `ping` and `tracert` commands rather than using raw sockets.
- Some routers/firewalls deprioritize or block ICMP. A hop can show loss even when later hops are healthy. Treat intermediate-hop loss as suspicious only when it continues through downstream hops or the final target.
- Traceroute can change while monitoring. Use the retrace dropdown to refresh the hop list periodically.
- The app is intentionally single-file Python code to make review and modification easy.
- The Tools page includes rendered output controls for copy/save and easier table readability.

## Dependencies

Installed automatically by the batch files:

- PySide6
- pyqtgraph
- PyInstaller

# Specter — Profile-Driven Network Scanner

Specter is an nmap-inspired network scanner built with an explicit
object-oriented design: `NetworkDiscovery`, `PortScanner`,
`ServiceFingerprinter`, and `OSFingerprinter` are each their own class,
coordinated by a `SpecterEngine` orchestrator. It adds built-in scan
**profiles** (quick / full / stealth) and an offline **outdated-version
advisory** lookup that flags a few well-documented old software banners
(e.g. vsftpd 2.3.4) with a note to check for known CVEs — informational
only, no exploit code.

> ⚠️ **Authorized use only.** Only scan systems/networks you own or have
> explicit written permission to test (e.g., your own lab VMs).

## Requirements

Python 3.8+, standard library only. `scapy` is optional, only needed for `--syn`.

## Usage

```bash
python specter_scan.py -t <target> [options]
```

### Examples

```bash
# Quick profile (default) with service + OS detection
python specter_scan.py -t 192.168.56.0/24 --sV --os

# Full profile (ports 1-1024 + common high ports), save CSV
python specter_scan.py -t 192.168.56.10 --profile full --sV --os -o report.csv

# Stealth profile: fewer threads, longer timeouts, same quick port set
python specter_scan.py -t 192.168.56.10 --profile stealth --sV

# Override the profile's ports entirely
python specter_scan.py -t 192.168.56.10 -p 1-100 --sV

# Host discovery only
python specter_scan.py -t 192.168.56.0/24 --discover-only
```

### Options

| Flag | Description |
|---|---|
| `-t, --target` | IP, CIDR, IP range, or hostname (required) |
| `--profile` | `quick` (default) / `full` / `stealth` — bundles a port set + timeout + thread-count |
| `-p, --ports` | Override the profile's ports, e.g. `22,80,443` or `1-1024` |
| `--sV` | Service/version detection + outdated-version advisories |
| `--os` | OS fingerprinting (TTL heuristic) |
| `--syn` | SYN scan (requires scapy + admin/root, auto-falls back) |
| `--discover-only` | Ping sweep only |
| `-o, --output` | Save to `.csv` or `.json` |
| `-q, --quiet` | Suppress live progress |

## Design notes (for code review slide)

- **OOP architecture**: `NetworkDiscovery`, `PortScanner`,
  `ServiceFingerprinter`, `OSFingerprinter` are independent, reusable
  classes; `SpecterEngine` composes them. `models.py` uses dataclasses
  (`HostResult`, `PortResult`, `ScanResult`) instead of raw dicts.
- **Scan profiles** (`config.py`): named presets (quick/full/stealth)
  bundling port list + timeout + thread count — same idea as nmap's `-T`
  timing templates or a vulnerability scanner's named policies.
- **Outdated-version advisories** (`fingerprint.py`): a small offline
  lookup table flagging banners matching known old software versions,
  purely informational (CVE reference numbers, no exploit code).
- **CSV export** (`reporter.py`): spreadsheet-friendly output alongside JSON.

## Project layout

```
specter/
  specter_scan.py
  specter/
    __init__.py
    models.py       dataclasses: PortResult, HostResult, ScanResult
    config.py         scan profiles + common-service reference table
    targets.py         target/port string parsing
    discovery.py        NetworkDiscovery class (ping sweep)
    scanner.py           PortScanner class (TCP connect / SYN)
    fingerprint.py        ServiceFingerprinter class + advisory table
    osdetect.py            OSFingerprinter class (TTL heuristic)
    reporter.py             ReportGenerator (console/CSV/JSON)
    engine.py                 SpecterEngine orchestrator
    cli.py                     argparse CLI
```

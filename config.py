"""
config.py
---------
Built-in scan profiles (a common pattern in real scanners: nmap has -T
timing templates, vulnerability scanners ship named policies). Each
profile bundles a port list + timeout + thread-count preset so a user
can pick a speed/thoroughness tradeoff with one flag instead of tuning
several.
"""
from dataclasses import dataclass
from typing import List


@dataclass
class ScanProfile:
    name: str
    description: str
    ports: List[int]
    timeout: float
    max_threads: int


_QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 3306, 3389, 5432, 5900, 8080]

_FULL_PORTS = list(range(1, 1025)) + [
    1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
    8443, 9200, 27017,
]

PROFILES = {
    "quick": ScanProfile(
        name="quick",
        description="Fast sweep of the most common ports (~17 ports). "
                     "Good for a first look at a subnet.",
        ports=_QUICK_PORTS, timeout=0.5, max_threads=150,
    ),
    "full": ScanProfile(
        name="full",
        description="All well-known ports (1-1024) plus common high "
                     "ports for popular services. Thorough, slower.",
        ports=sorted(set(_FULL_PORTS)), timeout=0.8, max_threads=200,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Same port set as 'quick' but scanned slowly with "
                     "low thread-count and longer timeouts, to minimize "
                     "the chance of tripping basic rate-based IDS alerts "
                     "during an authorized lab exercise.",
        ports=_QUICK_PORTS, timeout=1.5, max_threads=5,
    ),
}

# Fallback service-name table used when banner grabbing fails to
# positively identify a service.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle-db", 2049: "nfs", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

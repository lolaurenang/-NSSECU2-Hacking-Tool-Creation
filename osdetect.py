"""
osdetect.py
-----------
OSFingerprinter: TTL-based OS heuristic as a class, mirroring the same
well-documented signal used across all three project variants (initial
TTL 64=Linux/Unix, 128=Windows, 255=Cisco/Solaris/appliance), refined
with an open-port profile as a secondary corroborating signal.
"""
from .discovery import NetworkDiscovery

_TTL_TABLE = [(64, "Linux / Unix / macOS / Android"),
              (128, "Windows"),
              (255, "Cisco IOS / Solaris / Network Appliance")]


class OSFingerprinter:
    def __init__(self, timeout=1.0):
        self.timeout = timeout
        self._prober = NetworkDiscovery(timeout=timeout, verbose=False)

    def _guess_from_ttl(self, ttl):
        if ttl is None:
            return "Unknown (no ICMP response)"
        for ceiling, label in _TTL_TABLE:
            if ttl <= ceiling:
                return f"{label}  (TTL={ttl}, inferred initial TTL={ceiling})"
        return f"Unknown (unusual TTL={ttl})"

    def _refine(self, guess, open_ports):
        open_ports = set(open_ports or [])
        if "Unknown" in guess:
            if open_ports & {3389, 445, 135, 5985}:
                return "Likely Windows (based on open ports; TTL unavailable)"
            if open_ports & {22, 111, 2049}:
                return "Likely Linux/Unix (based on open ports; TTL unavailable)"
        return guess

    def fingerprint(self, ip, open_ports=None):
        _, ttl = self._prober._ping_once(ip)
        return self._refine(self._guess_from_ttl(ttl), open_ports)

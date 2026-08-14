"""
engine.py
---------
SpecterEngine: the orchestrator class that wires NetworkDiscovery,
PortScanner, ServiceFingerprinter, and OSFingerprinter together into one
scan pipeline, driven by a chosen ScanProfile. Keeping this coordination
logic in its own class (rather than a script-level function, as in the
other two variants) makes it straightforward to reuse Specter as a
library from other Python code, not just the CLI.
"""
import time

from .config import PROFILES
from .discovery import NetworkDiscovery
from .scanner import PortScanner
from .fingerprint import ServiceFingerprinter
from .osdetect import OSFingerprinter
from .models import ScanResult, HostResult
from .targets import parse_targets


class SpecterEngine:
    def __init__(self, profile_name="quick", custom_ports=None, syn=False,
                 service_detect=False, os_detect=False, discover_only=False,
                 verbose=True, logger=print):
        if profile_name not in PROFILES:
            raise ValueError(f"Unknown profile '{profile_name}'. "
                              f"Choices: {', '.join(PROFILES)}")
        self.profile = PROFILES[profile_name]
        self.ports = custom_ports if custom_ports is not None else self.profile.ports
        self.syn = syn
        self.service_detect = service_detect
        self.os_detect = os_detect
        self.discover_only = discover_only
        self.verbose = verbose
        self.logger = logger

        self.discovery = NetworkDiscovery(
            timeout=1.0, max_workers=min(self.profile.max_threads, 100),
            verbose=verbose, logger=logger,
        )
        self.scanner = PortScanner(
            timeout=self.profile.timeout, max_workers=self.profile.max_threads,
            method="syn" if syn else "connect", verbose=verbose, logger=logger,
        )
        self.fingerprinter = ServiceFingerprinter(timeout=1.5, verbose=verbose, logger=logger)
        self.os_fingerprinter = OSFingerprinter(timeout=1.0)

    def run(self, target_str) -> ScanResult:
        targets = parse_targets(target_str)
        start = time.time()
        result = ScanResult(target=target_str, profile=self.profile.name,
                             started=time.strftime("%Y-%m-%d %H:%M:%S"))

        if len(targets) == 1:
            live_hosts = [HostResult(ip=targets[0], alive=True, discovery_method="direct")]
        else:
            live_hosts = self.discovery.sweep(targets)

        for host in live_hosts:
            if not self.discover_only:
                if self.verbose:
                    self.logger(f"[*] Scanning {len(self.ports)} port(s) on {host.ip} "
                                f"[profile={self.profile.name}]...")
                host.ports = self.scanner.scan_host(host.ip, self.ports)

                if self.service_detect and host.ports:
                    self.fingerprinter.fingerprint_open_ports(host.ip, host.ports)

            if self.os_detect:
                host.os_guess = self.os_fingerprinter.fingerprint(
                    host.ip, open_ports=host.open_port_numbers
                )

            result.hosts.append(host)

        result.elapsed_seconds = round(time.time() - start, 2)
        return result

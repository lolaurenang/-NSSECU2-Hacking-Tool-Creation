"""
discovery.py
------------
NetworkDiscovery: encapsulates the ping-sweep behavior as a class with
configurable timeout/thread-count, so a caller can instantiate it once
and reuse it, or subclass it to change probing strategy (e.g. a student
extending this project could add an ARP-based LAN discovery subclass).
"""
import platform
import re
import socket
import subprocess
import concurrent.futures

from .models import HostResult

_IS_WINDOWS = platform.system().lower() == "windows"


class NetworkDiscovery:
    """Performs host-alive discovery (ICMP ping sweep with a TCP fallback
    for hosts that filter ICMP)."""

    FALLBACK_PORTS = (80, 443, 22, 3389, 445)

    def __init__(self, timeout=1.0, max_workers=100, verbose=True, logger=print):
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.logger = logger

    def _ping_once(self, ip):
        cmd = (
            ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
            if _IS_WINDOWS
            else ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]
        )
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=self.timeout + 1, text=True,
            )
            alive = result.returncode == 0
            ttl_match = re.search(r"[Tt][Tt][Ll][=:](\d+)", result.stdout)
            ttl = int(ttl_match.group(1)) if ttl_match else None
            return alive, ttl
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False, None

    def _tcp_fallback(self, ip):
        for port in self.FALLBACK_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        return True
            except (socket.timeout, OSError):
                continue
        return False

    def probe(self, ip) -> HostResult:
        alive, ttl = self._ping_once(ip)
        if alive:
            return HostResult(ip=ip, alive=True, ttl=ttl, discovery_method="icmp")
        if self._tcp_fallback(ip):
            return HostResult(ip=ip, alive=True, ttl=None, discovery_method="tcp-fallback")
        return HostResult(ip=ip, alive=False)

    def sweep(self, ip_list):
        """Probe a list of IPs concurrently; return only the live hosts."""
        live = []
        if self.verbose:
            self.logger(f"[*] Sweeping {len(ip_list)} address(es)...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.probe, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    if self.verbose:
                        self.logger(f"[!] Error probing {futures[future]}: {exc}")
                    continue
                if result.alive:
                    live.append(result)
                    if self.verbose:
                        self.logger(f"    [+] host up: {result.ip} (via {result.discovery_method})")

        live.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
        if self.verbose:
            self.logger(f"[*] {len(live)}/{len(ip_list)} host(s) alive.")
        return live

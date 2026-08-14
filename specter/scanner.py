"""
scanner.py
----------
PortScanner: TCP connect scanning as a class, with optional SYN scanning
via scapy when available and privileged. Kept as a class (rather than a
free function, as in NetHawk) so scan state/config (timeout, thread
count, method) lives on an instance that can be reused across hosts
within a single Specter run.
"""
import socket
import concurrent.futures

from .models import PortResult

try:
    from scapy.all import sr1, IP, TCP  # type: ignore
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    _SCAPY_AVAILABLE = False


class PortScanner:
    def __init__(self, timeout=0.75, max_workers=200, method="connect",
                 verbose=True, logger=print):
        self.timeout = timeout
        self.max_workers = max_workers
        self.method = "syn" if (method == "syn" and _SCAPY_AVAILABLE) else "connect"
        if method == "syn" and not _SCAPY_AVAILABLE and verbose:
            logger("[!] scapy unavailable - using TCP connect scan instead of SYN.")
        self.verbose = verbose
        self.logger = logger

    def _connect_probe(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
        except (socket.timeout, OSError):
            return False

    def _syn_probe(self, ip, port):
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None or not resp.haslayer(TCP):
                return False
            return resp.getlayer(TCP).flags == 0x12
        except PermissionError:
            return None
        except Exception:
            return None

    def scan_host(self, ip, ports):
        """Scan `ports` on a single host. Returns list[PortResult] (open only)."""
        probe_fn = self._syn_probe if self.method == "syn" else self._connect_probe
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(probe_fn, ip, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                except Exception as exc:  # noqa: BLE001
                    if self.verbose:
                        self.logger(f"[!] Error scanning {ip}:{port} - {exc}")
                    continue
                if is_open is None:  # SYN probe failed mid-run, retry via connect
                    is_open = self._connect_probe(ip, port)
                if is_open:
                    results.append(PortResult(port=port))
                    if self.verbose:
                        self.logger(f"    [+] {ip}:{port} OPEN")

        results.sort(key=lambda r: r.port)
        return results

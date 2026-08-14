"""
fingerprint.py
--------------
ServiceFingerprinter: banner grabbing + signature matching, same overall
approach as the other two tools (passive read -> generic nudge -> HTTP
probe, each on a fresh connection).

Distinguishing feature: an offline ADVISORY_TABLE that flags a small set
of well-documented, publicly-known outdated-version patterns (e.g. an
old vsftpd or OpenSSH banner) with a plain-text note to "check for known
CVEs / update this service." This is informational only - a lookup
table of published advisory references, not exploit code - the same
spirit as the "outdated software" checks built into many free/open-source
vulnerability scanners.
"""
import re
import socket

from .config import COMMON_SERVICES
from .models import PortResult

_SERVER_FIRST_PORTS = {21, 22, 23, 25, 110, 143}
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: specter-scan\r\nConnection: close\r\n\r\n"
_GENERIC_PROBE = b"\r\n"

_SIGNATURES = [
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", re.I), "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-([\w.-]+)", re.I), "SSH"),
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"Server:\s*Apache/([\d.]+)", re.I), "Apache httpd"),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS"),
    (re.compile(r"Server:\s*([^\r\n]+)", re.I), "HTTP server"),
    (re.compile(r"220[- ].*?vsftpd\s+([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"220[- ].*?ProFTPD\s+([\d.]+)", re.I), "ProFTPD"),
    (re.compile(r"220[- ].*?Postfix", re.I), "Postfix smtpd"),
    (re.compile(r"\+OK.*?Dovecot", re.I), "Dovecot pop3d"),
    (re.compile(r"redis_version:([\d.]+)", re.I), "Redis"),
]

# Small, illustrative table: (service, version-prefix) -> advisory note.
# Informational only - references publicly documented advisories so the
# user knows to go look them up; does not include exploit details.
ADVISORY_TABLE = {
    ("vsftpd", "2.3.4"): "Matches a version with a well-documented public "
                          "backdoor advisory (CVE-2011-2523). Verify and update.",
    ("OpenSSH", "6."): "OpenSSH 6.x is end-of-life; several CVEs were patched "
                        "in later releases. Recommend upgrading.",
    ("OpenSSH", "7.1"): "Older OpenSSH 7.x releases have known CVEs patched in "
                         "later versions. Recommend upgrading.",
    ("Apache httpd", "2.2"): "Apache 2.2.x is end-of-life (no security patches "
                              "since 2017). Recommend upgrading to 2.4.x+.",
    ("Microsoft IIS", "6.0"): "IIS 6.0 is end-of-life and unsupported. "
                               "Recommend upgrading the host OS/IIS version.",
}


def _check_advisory(service, version):
    if not version:
        return None
    for (svc_key, ver_prefix), note in ADVISORY_TABLE.items():
        if service == svc_key and version.startswith(ver_prefix):
            return note
    return None


class ServiceFingerprinter:
    def __init__(self, timeout=1.5, verbose=True, logger=print):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logger

    def _connect_and_read(self, ip, port, payload, max_bytes=1024, timeout=None):
        timeout = timeout or self.timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                if payload:
                    s.sendall(payload)
                return s.recv(max_bytes)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return b""

    def grab_banner(self, ip, port):
        if port in _SERVER_FIRST_PORTS:
            raw = self._connect_and_read(ip, port, None)
        elif port in (80, 8080, 8443, 8000, 8888, 3000, 5000, 9000):
            raw = self._connect_and_read(ip, port, _HTTP_PROBE, max_bytes=2048)
        else:
            t = min(self.timeout, 0.6)
            raw = self._connect_and_read(ip, port, None, timeout=t)
            if not raw:
                raw = self._connect_and_read(ip, port, _GENERIC_PROBE, timeout=t)
            if not raw:
                raw = self._connect_and_read(ip, port, _HTTP_PROBE, max_bytes=2048, timeout=t)
        return raw.decode(errors="replace").strip()

    def identify(self, ip, port) -> PortResult:
        banner = self.grab_banner(ip, port)
        service, version = COMMON_SERVICES.get(port, "unknown"), None

        for pattern, name in _SIGNATURES:
            m = pattern.search(banner)
            if m:
                service = name
                version = m.group(1) if m.groups() else None
                break

        advisory = _check_advisory(service, version)
        result = PortResult(port=port, service=service, version=version,
                             banner=banner[:200], advisory=advisory)
        if self.verbose:
            ver = f" {version}" if version else ""
            self.logger(f"    [i] {ip}:{port} -> {service}{ver}"
                        + (f"  ADVISORY: {advisory}" if advisory else ""))
        return result

    def fingerprint_open_ports(self, ip, port_results):
        """Given a host's already-discovered open PortResults, fill in
        service/version/advisory info on each (mutates and returns the list)."""
        for pr in port_results:
            detected = self.identify(ip, pr.port)
            pr.service, pr.version = detected.service, detected.version
            pr.banner, pr.advisory = detected.banner, detected.advisory
        return port_results

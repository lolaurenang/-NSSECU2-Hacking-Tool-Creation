"""
models.py
---------
Plain dataclasses used to pass structured results between Specter's
components, instead of raw dicts. Keeps type intent explicit and gives
IDE autocomplete/type-checking support - a deliberate code-quality choice
for this project.
"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PortResult:
    port: int
    is_open: bool = True
    service: str = "unknown"
    version: Optional[str] = None
    banner: str = ""
    advisory: Optional[str] = None  # outdated-version hint, if any


@dataclass
class HostResult:
    ip: str
    alive: bool = True
    ttl: Optional[int] = None
    discovery_method: Optional[str] = None
    os_guess: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)

    @property
    def open_port_numbers(self):
        return sorted(p.port for p in self.ports if p.is_open)


@dataclass
class ScanResult:
    target: str
    profile: str
    started: str
    elapsed_seconds: float = 0.0
    hosts: List[HostResult] = field(default_factory=list)

    def to_dict(self):
        return {
            "target": self.target,
            "profile": self.profile,
            "started": self.started,
            "elapsed_seconds": self.elapsed_seconds,
            "hosts": [
                {
                    "ip": h.ip,
                    "os_guess": h.os_guess,
                    "open_ports": [
                        {
                            "port": p.port,
                            "service": p.service,
                            "version": p.version,
                            "advisory": p.advisory,
                        }
                        for p in h.ports if p.is_open
                    ],
                }
                for h in self.hosts
            ],
        }

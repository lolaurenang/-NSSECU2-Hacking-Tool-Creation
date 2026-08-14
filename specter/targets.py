"""
targets.py
----------
Target and port-string parsing helpers, kept separate from config.py
(reference data) and the discovery/scanner classes (behavior) to keep
each module focused on one responsibility.
"""
import ipaddress
import socket


def parse_targets(target_str):
    target_str = target_str.strip()

    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR '{target_str}': {e}")
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]

    if "-" in target_str and target_str.count(".") >= 3:
        start_s, end_s = target_str.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(start_s.strip())
            end_s = end_s.strip()
            if "." not in end_s:
                base = start_s.strip().rsplit(".", 1)[0]
                end_ip = ipaddress.ip_address(f"{base}.{end_s}")
            else:
                end_ip = ipaddress.ip_address(end_s)
            if int(end_ip) < int(start_ip):
                raise ValueError("range end before start")
        except ValueError as e:
            raise ValueError(f"Invalid IP range '{target_str}': {e}")
        return [str(ipaddress.ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]

    try:
        ipaddress.ip_address(target_str)
        return [target_str]
    except ValueError:
        pass

    try:
        return [socket.gethostbyname(target_str)]
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError(f"Could not parse or resolve target '{target_str}'")


def parse_ports(port_str):
    port_str = port_str.strip().lower()
    ports = set()
    for chunk in port_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = (int(x) for x in chunk.split("-", 1))
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"Invalid port range '{chunk}'")
            ports.update(range(lo, hi + 1))
        else:
            p = int(chunk)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    if not ports:
        raise ValueError("No valid ports parsed")
    return sorted(ports)

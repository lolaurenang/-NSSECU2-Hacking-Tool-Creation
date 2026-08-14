"""
cli.py
------
Command-line interface for Specter. Thin argparse layer over SpecterEngine
so the engine itself stays usable as a library.
"""
import argparse
import sys

from . import __version__
from .config import PROFILES
from .targets import parse_ports
from .engine import SpecterEngine
from .reporter import ReportGenerator

BANNER = f"""
   _____                     __
  / ___/____  ___  _____/ /____  _____
  \\__ \\/ __ \\/ _ \\/ ___/ __/ _ \\/ ___/
 ___/ / /_/ /  __/ /__/ /_/  __/ /
/____/ .___/\\___/\\___/\\__/\\___/_/
    /_/           Specter v{__version__} - profile-driven network scanner
                   Authorized security testing / lab use only.
"""


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="specter",
        description="Specter - OOP, profile-driven network scanner: host "
                     "discovery, port scanning, service/version detection "
                     "(with outdated-version advisories), OS fingerprinting.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-t", "--target", required=True,
                    help="IP, CIDR, IP range, or hostname.")
    p.add_argument("--profile", choices=list(PROFILES), default="quick",
                    help="Built-in scan profile controlling port set/speed. "
                         f"{'; '.join(f'{n}: {pr.description}' for n, pr in PROFILES.items())}")
    p.add_argument("-p", "--ports",
                    help="Override the profile's port list, e.g. '22,80,443' or '1-1024'.")
    p.add_argument("--sV", dest="service_detect", action="store_true",
                    help="Enable service/version detection + outdated-version advisories.")
    p.add_argument("--os", dest="os_detect", action="store_true",
                    help="Enable OS fingerprinting.")
    p.add_argument("--syn", action="store_true",
                    help="Use SYN scan (requires scapy + admin/root); falls back to connect scan.")
    p.add_argument("--discover-only", action="store_true",
                    help="Only run host discovery.")
    p.add_argument("-o", "--output", help="Save report to .csv or .json.")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress live progress output.")
    return p


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    verbose = not args.quiet

    if verbose:
        print(BANNER)

    custom_ports = None
    if args.ports:
        try:
            custom_ports = parse_ports(args.ports)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    engine = SpecterEngine(
        profile_name=args.profile, custom_ports=custom_ports, syn=args.syn,
        service_detect=args.service_detect, os_detect=args.os_detect,
        discover_only=args.discover_only, verbose=verbose,
    )

    try:
        result = engine.run(args.target)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.", file=sys.stderr)
        sys.exit(130)

    reporter = ReportGenerator(result)
    reporter.print_console()
    if args.output:
        reporter.save(args.output)
        print(f"[*] Report saved to {args.output}")


if __name__ == "__main__":
    main()

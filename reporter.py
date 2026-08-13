"""
reporter.py
-----------
ReportGenerator: console table printing plus CSV/JSON export. CSV is the
distinguishing export format here (vs. NetHawk's txt/json and
ShadowSweep's HTML) - convenient for pulling results into a spreadsheet
for the project's written report/appendix.
"""
import csv
import json


class ReportGenerator:
    def __init__(self, scan_result):
        self.result = scan_result

    def print_console(self):
        r = self.result
        print("\n" + "=" * 62)
        print(f" Specter Scan Report - {r.target}  [profile: {r.profile}]")
        print("=" * 62)
        if not r.hosts:
            print("No live hosts discovered.")
        for host in r.hosts:
            print(f"\nHost: {host.ip}")
            if host.os_guess:
                print(f"  OS guess : {host.os_guess}")
            open_ports = [p for p in host.ports if p.is_open]
            if open_ports:
                print(f"  {'PORT':<8}{'SERVICE':<18}{'VERSION':<16}{'ADVISORY'}")
                for p in open_ports:
                    ver = p.version or ""
                    adv = p.advisory or ""
                    print(f"  {p.port:<8}{p.service:<18}{ver:<16}{adv}")
            else:
                print("  No open ports found (or scan skipped)")
        print(f"\nDone in {r.elapsed_seconds}s")
        print("=" * 62 + "\n")

    def to_json(self, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.result.to_dict(), f, indent=2)

    def to_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["host", "os_guess", "port", "service", "version", "advisory"])
            for host in self.result.hosts:
                open_ports = [p for p in host.ports if p.is_open]
                if not open_ports:
                    writer.writerow([host.ip, host.os_guess or "", "", "", "", ""])
                    continue
                for p in open_ports:
                    writer.writerow([host.ip, host.os_guess or "", p.port,
                                      p.service, p.version or "", p.advisory or ""])

    def save(self, path):
        if path.lower().endswith(".csv"):
            self.to_csv(path)
        elif path.lower().endswith(".json"):
            self.to_json(path)
        else:
            self.to_json(path)

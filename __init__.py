"""
Specter - a profile-driven, object-oriented network reconnaissance scanner.

Where NetHawk uses a functional/module pipeline and ShadowSweep uses
asyncio coroutines, Specter is built around explicit classes for each
capability (NetworkDiscovery, PortScanner, ServiceFingerprinter,
OSFingerprinter) coordinated by a SpecterEngine orchestrator, and adds
built-in scan *profiles* (quick / full / stealth) plus an offline
outdated-version advisory lookup (flagging banners that match known-old
software versions so the user knows to check for CVEs / patch - no
exploit code, just a documentation-style hint).
"""
__version__ = "1.0.0"

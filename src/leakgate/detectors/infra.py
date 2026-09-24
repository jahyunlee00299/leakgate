"""Infrastructure fingerprints: home-directory usernames, org tenants, private IPs.

The reported span is the identifying segment only (the username, the tenant,
the address), so redaction keeps the rest of a traceback readable:
`C:\\Users\\<name>\\proj\\run.py` becomes `C:\\Users\\<USER>\\proj\\run.py`.
"""
from __future__ import annotations

import ipaddress
import re

from leakgate.detectors.base import Rule, scan_rules
from leakgate.finding import Finding

GENERIC_USERS = frozenset({
    "user", "users", "username", "you", "yourname", "your_name", "me", "name", "public",
    "default", "default user", "all users", "shared", "runner", "ubuntu", "vagrant",
    "docker", "admin", "guest", "someone", "foo", "example", "x", "...", "*", "~",
    # CI build agents: their paths leak into compiled artefacts and mean nobody.
    "runneradmin", "appveyor", "vssadministrator", "buildagent", "jenkins", "travis",
    "circleci", "builder", "build", "ci",
})


def _username(m: re.Match) -> str | None:
    v = m.group("v")
    low = v.lower()
    if low in GENERIC_USERS or low.startswith(("$", "%", "<", "{", "[")) or "*" in v:
        return None
    return v


def _tenant(m: re.Match) -> str | None:
    v = m.group("v").strip()
    if not v or v.lower() in {"personal", "개인"} or v.startswith(("<", "$", "%")):
        return None
    return v


def _private_ip(m: re.Match) -> str | None:
    # Explicit ranges, not ip.is_private: that also covers the RFC 5737
    # documentation blocks (203.0.113.0/24 …), which appear in every tutorial.
    try:
        ip = ipaddress.IPv4Address(m.group(0))
    except ValueError:
        return None
    if str(ip) in _EXAMPLE_IPS:
        return None
    return str(ip) if any(ip in net for net in _INTERNAL_NETS) else None


_INTERNAL_NETS = [ipaddress.IPv4Network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "100.64.0.0/10",                                # Tailscale / carrier-grade NAT
)]
_INTERNAL_TLD = r"(?-i:local|corp|intranet|lan|home\.arpa)"
# Router defaults and textbook examples; they identify no one's network.
_EXAMPLE_IPS = frozenset({"10.0.0.1", "10.0.0.2", "10.0.0.0", "192.168.0.1", "192.168.1.1",
                          "192.168.0.0", "192.168.1.0", "172.16.0.1", "172.16.0.0"})
_SEP = r"(?:\\\\|\\|/)+"                            # \, escaped \\ (JSON), or /

RULES: list[Rule] = [
    ("windows-home-path", re.compile(r"(?i)\b[A-Z]:" + _SEP + r"Users" + _SEP + r"(?P<v>[^\\/\s\"':*?<>|]+)"),
     _username),
    ("posix-home-path", re.compile(r"(?<![\w.~])/(?:[a-z]/)?(?:home|Users)/(?P<v>[^/\s\"':*?<>|]+)"),
     _username),
    ("onedrive-tenant", re.compile(r"OneDrive\s*-\s*(?P<v>[^\\/\n\"'<>|]+?)\s*(?=[\\/\"']|$)"), _tenant),
    # `(?!/\d)`: CIDR notation (10.0.0.0/8) names a range, not a host.
    ("private-ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]|/\d)"), _private_ip),
    ("sharepoint-tenant", re.compile(r"(?i)https?://(?P<v>[a-z0-9\-]+?)(?:-my|-admin)?\.sharepoint\.com"), _tenant),
    ("sharepoint-personal", re.compile(r"(?i)\.sharepoint\.com/personal/(?P<v>[A-Za-z0-9_.\-]+)"), _tenant),
    ("internal-host", re.compile(
        # Bare hosts need two labels before the TLD and no trailing extension:
        # `pre-commit.local` and `settings.local.json` are files, not machines.
        # `.internal` only after `@` or `://`: bare, it is a JS property or a
        # published cloud hostname (metadata.google.internal, ec2.internal).
        r"(?i)(?<![\w.\-])(?P<v>(?:[a-z0-9_.\-]+@)?[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\." + _INTERNAL_TLD + r")(?![\w\-]|\.\w)"
        r"|(?:@|://)(?P<w>[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?-i:internal|intra))(?![\w\-])"),
     lambda m: m.group("v") or m.group("w")),
]


class InfraDetector:
    name = "infra"

    def scan(self, text: str) -> list[Finding]:
        return scan_rules(text, RULES, "infra")


def _register_gates() -> None:
    from leakgate.detectors.base import gate
    gate("windows-home-path", "(?i)users")
    gate("posix-home-path", "/home/|/Users/")
    gate("onedrive-tenant", "OneDrive")
    gate("private-ipv4", r"\d\.\d")
    gate("sharepoint-tenant", "(?i)sharepoint")
    gate("sharepoint-personal", "(?i)sharepoint")
    gate("internal-host", r"\.(?:local|corp|intranet|lan|home\.arpa|internal|intra)\b")


_register_gates()

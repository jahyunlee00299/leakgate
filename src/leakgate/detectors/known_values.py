"""Exact-match your own real credentials, whatever their format.

Pattern scanners miss a token whose prefix is generic. If you point leakgate at
the file where your secrets actually live (a secrets.json, a .env), every
literal value in it becomes a search needle — so your own key is caught with
certainty. Values are held in memory only and never printed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from leakgate.finding import Finding

SECRET_KEY_NAME = re.compile(r"token|key|pat$|password|passwd|secret|credential|auth", re.I)
MIN_LEN = 8


def load_values(path: str | Path, all_values: bool = False) -> list[str]:
    """Read secret values from .json (nested ok), .env / KEY=VALUE, or one-per-line text."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    out: list[str] = []

    def keep(key: str, val: str):
        val = val.strip().strip("\"'")
        if len(val) >= MIN_LEN and (all_values or SECRET_KEY_NAME.search(key)):
            out.append(val)

    if p.suffix.lower() == ".json":
        def walk(v, k=""):
            if isinstance(v, str):
                keep(k, v)
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    walk(vv, kk)
            elif isinstance(v, list):
                for vv in v:
                    walk(vv, k)
        walk(json.loads(text))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.removeprefix("export ").partition("=")
                keep(k.strip(), v)
            else:
                keep("secret", line)        # bare one-value-per-line file
    return sorted(set(out), key=len, reverse=True)


class KnownValueDetector:
    name = "known-values"

    def __init__(self, values: list[str]):
        vals = [v for v in values if len(v) >= MIN_LEN]
        self.rx = re.compile("|".join(re.escape(v) for v in vals)) if vals else None

    def scan(self, text: str) -> list[Finding]:
        if not self.rx:
            return []
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            for m in self.rx.finditer(line):
                out.append(Finding("secret", "known-value", n, m.start(), m.end(), m.group(0)))
        return out

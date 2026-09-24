"""Rewrite files with findings replaced, without ever corrupting them.

Guarantees, each learned from a real incident:
- Binary files are never opened (a UTF-8 round-trip destroyed JPEGs and PDFs).
- A JSON/JSONL file is written only if every line that parsed before still parses.
- The write is atomic (temp file + rename) so a crash never leaves half a file.
- An optional backup copies the RAW bytes, not decoded text, so it can restore.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from leakgate.finding import Finding

REPLACEMENT = {
    "secret": "[REDACTED:{rule}]",
    "pii": "[PII:{rule}]",
    "custom": "[PRIVATE]",
}
INFRA_REPLACEMENT = {
    "windows-home-path": "<USER>",
    "posix-home-path": "<USER>",
    "onedrive-tenant": "<ORG>",
    "private-ipv4": "<PRIVATE_IP>",
    "sharepoint-tenant": "<ORG>",
    "sharepoint-personal": "<USER>",
    "internal-host": "<INTERNAL_HOST>",
}


class UnsafeRedaction(RuntimeError):
    pass


def replacement_for(f: Finding) -> str:
    if f.category == "infra":
        return INFRA_REPLACEMENT.get(f.rule, "<INFRA>")
    return REPLACEMENT.get(f.category, "[REDACTED]").format(rule=f.rule.split(":")[-1])


def redact_text(text: str, findings: list[Finding]) -> str:
    by_line: dict[int, list[Finding]] = {}
    for f in findings:
        by_line.setdefault(f.line, []).append(f)
    lines = text.splitlines(keepends=True)
    for n, fs in by_line.items():
        if not 0 < n <= len(lines):
            continue
        line = lines[n - 1]
        for f in sorted(fs, key=lambda x: x.start, reverse=True):
            if line[f.start:f.end] != f.value:       # stale finding: never guess
                raise UnsafeRedaction(f"line {n}: span no longer matches its value")
            line = line[:f.start] + replacement_for(f) + line[f.end:]
        lines[n - 1] = line
    return "".join(lines)


def _json_ok_lines(text: str) -> set[int]:
    ok = set()
    for i, line in enumerate(text.splitlines()):
        try:
            json.loads(line)
            ok.add(i)
        except ValueError:
            pass
    return ok


def redact_file(path: str | Path, findings: list[Finding], backup: bool = False) -> int:
    """Apply findings to one file. Returns the number of spans replaced."""
    p = Path(path)
    if not findings:
        return 0
    raw = p.read_bytes()
    text = raw.decode("utf-8", errors="strict")     # refuse to rewrite undecodable files
    new = redact_text(text, findings)
    suffix = p.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        if not _json_ok_lines(text) <= _json_ok_lines(new):
            raise UnsafeRedaction(f"{p}: redaction would break JSON lines; left untouched")
    elif suffix == ".json":
        try:
            json.loads(text)
        except ValueError:
            pass
        else:
            try:
                json.loads(new)
            except ValueError as e:
                raise UnsafeRedaction(f"{p}: redaction would break JSON; left untouched") from e
    if backup:
        bak = p.with_name(p.name + ".leakgate.bak")
        if not bak.exists():
            shutil.copy2(p, bak)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(new)
        shutil.copymode(p, tmp)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return len(findings)

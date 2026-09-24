"""Render findings. No renderer ever prints a raw value."""
from __future__ import annotations

import json
from collections import Counter

from leakgate import __version__
from leakgate.finding import Finding


def text(findings: list[Finding], n_files: int, notes: list[str]) -> str:
    out = [f"{f.path or '<stdin>'}:{f.line}:{f.start + 1}  {f.category:<6} {f.rule:<28} {f.masked}"
           for f in findings]
    by_cat = Counter(f.category for f in findings)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(by_cat.items())) or "clean"
    out.append(f"\nleakgate: {len(findings)} finding(s) in {n_files} file(s) — {summary}")
    out += [f"note: engine unavailable — {n}" for n in notes]
    return "\n".join(out)


def as_json(findings: list[Finding], n_files: int, notes: list[str]) -> str:
    return json.dumps({"version": __version__, "files_scanned": n_files,
                       "unavailable_engines": notes,
                       "findings": [f.to_dict() for f in findings]}, ensure_ascii=False, indent=1)


def sarif(findings: list[Finding], n_files: int, notes: list[str]) -> str:
    rules = sorted({f.rule for f in findings})
    results = [{
        "ruleId": f.rule,
        "level": "error" if f.category == "secret" else "warning",
        "message": {"text": f"{f.category}: {f.rule} ({f.masked})"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": (f.path or "stdin").replace("\\", "/")},
            "region": {"startLine": f.line, "startColumn": f.start + 1, "endColumn": f.end + 1}}}],
    } for f in findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "leakgate", "version": __version__,
                                      "rules": [{"id": r} for r in rules]}},
                  "results": results}]}, indent=1)


RENDERERS = {"text": text, "json": as_json, "sarif": sarif}

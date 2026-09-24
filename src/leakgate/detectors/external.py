"""Optional adapters around established scanners.

leakgate does not reimplement what mature tools already do well: gitleaks
carries ~200 maintained vendor rules, maskingtape and ko-pii carry tuned Korean
PII rules. Each adapter is used only when its tool is installed and requested;
an unavailable engine is reported, never silently skipped.
"""
from __future__ import annotations

import bisect
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from leakgate.finding import Finding


class EngineUnavailable(RuntimeError):
    pass


def _offsets_to_findings(text: str, spans, engine: str, category: str) -> list[Finding]:
    """Convert whole-text (start, end, rule) spans into line-relative findings."""
    starts, bodies, pos = [], [], 0
    for raw in text.splitlines(keepends=True):
        starts.append(pos)
        bodies.append(raw.rstrip("\r\n"))
        pos += len(raw)
    out = []
    for start, end, rule in spans:
        i = max(bisect.bisect_right(starts, start) - 1, 0)
        body = bodies[i] if bodies else ""
        s = start - (starts[i] if starts else 0)
        e = min(end - (starts[i] if starts else 0), len(body))   # a span never crosses a line
        out.append(Finding(category, rule, i + 1, s, e, body[s:e], engine))
    return out


class GitleaksDetector:
    name = "gitleaks"

    def __init__(self, binary: str | None = None):
        self.binary = binary or shutil.which("gitleaks")
        if not self.binary:
            raise EngineUnavailable("gitleaks binary not found on PATH")

    def scan(self, text: str) -> list[Finding]:
        with tempfile.TemporaryDirectory() as d:
            src, rep = Path(d) / "input.txt", Path(d) / "report.json"
            src.write_text(text, encoding="utf-8")
            subprocess.run([self.binary, "dir", str(src), "-f", "json", "-r", str(rep), "--no-banner",
                            "-l", "error", "--exit-code", "0", "--redact=0"],
                           check=True, capture_output=True, env={**os.environ, "NO_COLOR": "1"})
            data = json.loads(rep.read_text(encoding="utf-8") or "[]")
        lines = text.splitlines()
        out = []
        for x in data:
            n = x["StartLine"]
            line = lines[n - 1] if 0 < n <= len(lines) else ""
            secret = x.get("Secret") or x.get("Match", "")
            s = line.find(secret) if secret else -1
            s, e = (s, s + len(secret)) if s >= 0 else (0, len(line))
            out.append(Finding("secret", f"gitleaks:{x.get('RuleID', 'rule')}", n, s, e, line[s:e], self.name))
        return out


class _PythonPiiEngine:
    name = ""
    module = ""

    def __init__(self):
        try:
            self._mod = __import__(self.module)
        except ImportError as e:
            raise EngineUnavailable(f"python package '{self.module}' not installed") from e


class MaskingtapeDetector(_PythonPiiEngine):
    name, module = "maskingtape", "maskingtape"

    def __init__(self):
        super().__init__()
        self._pipe = self._mod.Pipeline()

    def scan(self, text: str) -> list[Finding]:
        spans = [(d.start, d.end, f"maskingtape:{d.kind}") for d in self._pipe.scan(text)]
        return _offsets_to_findings(text, spans, self.name, "pii")


class KoPiiDetector(_PythonPiiEngine):
    name, module = "ko-pii", "ko_pii"

    def scan(self, text: str) -> list[Finding]:
        spans = [(d.start, d.end, f"ko-pii:{d.label.lower()}") for d in self._mod.detect_all(text)]
        return _offsets_to_findings(text, spans, self.name, "pii")


ENGINES = {"gitleaks": GitleaksDetector, "maskingtape": MaskingtapeDetector, "ko-pii": KoPiiDetector}

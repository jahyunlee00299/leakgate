"""Run the configured detectors over files and merge their findings."""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Iterator

from leakgate.config import Config
from leakgate.detectors.custom import CustomDictionaryDetector
from leakgate.detectors.external import ENGINES
from leakgate.detectors.infra import InfraDetector
from leakgate.detectors.known_values import KnownValueDetector, load_values
from leakgate.detectors.kr_pii import KoreanPiiDetector
from leakgate.detectors.secrets import SecretDetector
from leakgate.finding import Finding

SUPPRESS_MARK = "leakgate:allow"
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".eggs"}
# Rewriting a binary as text destroys it, so these are never opened.
BINARY_SUFFIXES = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".ico", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl", ".egg",
    ".xlsx", ".xlsm", ".xls", ".docx", ".doc", ".pptx", ".ppt", ".odt", ".ods", ".hwp", ".hwpx",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".pyo", ".class",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg", ".ttf", ".otf", ".woff", ".woff2",
    ".db", ".sqlite", ".sqlite3", ".npy", ".npz", ".pkl", ".parquet", ".h5",
}
MAX_BYTES = 10 * 1024 * 1024
# When two detectors report overlapping spans, the more specific one wins.
PRIORITY = {"known-value": 0, "secret": 1, "custom": 2, "pii": 3, "infra": 4}


def is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return True
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


class Scanner:
    def __init__(self, config: Config, extra_known: list[str] | None = None):
        self.config = config
        self.detectors = []
        self.unavailable: list[str] = []
        cats = set(config.categories)
        if "secret" in cats:
            self.detectors.append(SecretDetector())
        if "pii" in cats:
            self.detectors.append(KoreanPiiDetector())
        if "infra" in cats:
            self.detectors.append(InfraDetector())
        if "custom" in cats and (config.terms or config.patterns or config.metrics):
            self.detectors.append(CustomDictionaryDetector(
                config.terms, config.patterns, config.metrics, config.metric_window))
        values: list[str] = []
        for f in [*config.known_secrets, *(extra_known or [])]:
            values += load_values(f)
        if values:
            self.detectors.append(KnownValueDetector(values))
        for name in config.engines:
            try:
                self.detectors.append(ENGINES[name]())
            except KeyError:
                raise ValueError(f"unknown engine '{name}' (choose from {sorted(ENGINES)})")
            except Exception as e:  # EngineUnavailable and tool crashes alike
                self.unavailable.append(f"{name}: {e}")
        self.allow = [re.compile(a) for a in config.allow]

    # -- text -----------------------------------------------------------
    def scan_text(self, text: str, path: str = "") -> list[Finding]:
        raw: list[Finding] = []
        for d in self.detectors:
            raw += d.scan(text)
        lines = text.splitlines()
        kept = []
        for f in raw:
            if 0 < f.line <= len(lines) and SUPPRESS_MARK in lines[f.line - 1]:
                continue
            if any(a.search(f.value) for a in self.allow):
                continue
            kept.append(replace(f, path=path))
        return _dedupe(kept)

    # -- files ----------------------------------------------------------
    def iter_files(self, targets: list[str]) -> Iterator[Path]:
        for t in targets:
            p = Path(t)
            if p.is_file():
                if not is_binary(p):
                    yield p
                continue
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for name in files:
                    fp = Path(root) / name
                    rel = fp.relative_to(p).as_posix()
                    if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fp.as_posix(), g)
                           for g in self.config.exclude):
                        continue
                    try:
                        if fp.stat().st_size > MAX_BYTES or is_binary(fp):
                            continue
                    except OSError:
                        continue
                    yield fp

    def scan_paths(self, targets: list[str]) -> tuple[list[Finding], int]:
        findings, n = [], 0
        for fp in self.iter_files(targets):
            n += 1
            text = fp.read_text(encoding="utf-8", errors="replace")
            findings += self.scan_text(text, str(fp))
        return findings, n


def _rank(f: Finding) -> tuple:
    return (PRIORITY.get(f.rule if f.rule == "known-value" else f.category, 9), -(f.end - f.start))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per overlapping span on a line (highest priority, then longest)."""
    out: list[Finding] = []
    for f in sorted(findings, key=_rank):
        if any(o.line == f.line and o.start < f.end and f.start < o.end for o in out):
            continue
        out.append(f)
    return sorted(out, key=lambda f: (f.path, f.line, f.start))

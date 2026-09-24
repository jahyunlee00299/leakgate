"""`.leakgate.toml` loading. Every field is optional."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAME = ".leakgate.toml"

SAMPLE = '''# leakgate configuration — every key is optional.

# Categories to report: secret, pii, infra, custom
categories = ["secret", "pii", "infra", "custom"]

# Extra engines, used only if installed: "gitleaks" (binary on PATH),
# "maskingtape", "ko-pii" (pip packages).
engines = []

# Files whose VALUES are your real secrets (json / .env / one-per-line).
# They are matched literally and never printed.
known_secrets = []

# Glob patterns (relative to the scan root) to skip.
exclude = ["**/.venv/**", "**/node_modules/**"]

# Regexes; a finding whose value matches any of these is dropped.
allow = []

[custom]
# Unpublished project / codename / private repo names (case-insensitive, whole word).
terms = []
# Arbitrary regexes for organisation-specific identifiers.
patterns = []
# Metric words whose nearby NUMBER is sensitive, e.g. ["yield", "titer", "MPSP"].
metrics = []
metric_window = 40
'''


@dataclass
class Config:
    categories: list[str] = field(default_factory=lambda: ["secret", "pii", "infra", "custom"])
    engines: list[str] = field(default_factory=list)
    known_secrets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    terms: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    metrics: list[str] = field(default_factory=list)
    metric_window: int = 40
    base_dir: Path = field(default_factory=Path.cwd)


def load(path: str | Path | None = None, search_from: Path | None = None) -> Config:
    if path is None:
        start = (search_from or Path.cwd()).resolve()
        start = start if start.is_dir() else start.parent
        for d in (start, *start.parents):
            if (d / CONFIG_NAME).is_file():
                path = d / CONFIG_NAME
                break
    if path is None:
        return Config()
    p = Path(path)
    data = tomllib.loads(p.read_text(encoding="utf-8"))
    custom = data.get("custom", {})
    unknown = set(data) - {"categories", "engines", "known_secrets", "exclude", "allow", "custom"}
    if unknown:
        raise ValueError(f"{p}: unknown key(s) {sorted(unknown)}")
    return Config(
        categories=data.get("categories", Config().categories),
        engines=data.get("engines", []),
        known_secrets=[str((p.parent / k).expanduser()) if not Path(k).expanduser().is_absolute()
                       else str(Path(k).expanduser()) for k in data.get("known_secrets", [])],
        exclude=data.get("exclude", []),
        allow=data.get("allow", []),
        terms=custom.get("terms", []),
        patterns=custom.get("patterns", []),
        metrics=custom.get("metrics", []),
        metric_window=int(custom.get("metric_window", 40)),
        base_dir=p.parent,
    )

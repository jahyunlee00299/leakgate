"""Detector contract and the shared line-scanning helper."""
from __future__ import annotations

import re
from typing import Callable, Iterable, Protocol

from leakgate.finding import Finding


class Detector(Protocol):
    name: str

    def scan(self, text: str) -> list[Finding]:
        """Return findings for `text` (a whole file). Lines are 1-based."""
        ...


# A rule is (rule_name, regex, optional validator). The validator receives the
# match and returns the exact span value to report, or None to reject it.
Validator = Callable[[re.Match], "str | None"]
Rule = tuple[str, re.Pattern, "Validator | None"]


def default_value(m: re.Match) -> str:
    """Report the named group `v` when present, else the whole match."""
    if "v" in m.re.groupindex and m.group("v") is not None:
        return m.group("v")
    return m.group(0)


# Cheap per-rule gate: a rule's full regex runs only on lines that contain one
# of its anchor substrings. Measured 3x faster on 16 MB of site-packages, and a
# rule without an entry here simply always runs.
GATES: dict[str, re.Pattern] = {}


def gate(name: str, pattern: str, flags: int = 0) -> None:
    GATES[name] = re.compile(pattern, flags)


def scan_rules(text: str, rules: Iterable[Rule], category: str,
               engine: str = "builtin") -> list[Finding]:
    out: list[Finding] = []
    rules = [(n, rx, v, GATES.get(n)) for n, rx, v in rules]
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, rx, validate, g_rx in rules:
            if g_rx is not None and not g_rx.search(line):
                continue
            for m in rx.finditer(line):
                value = validate(m) if validate else default_value(m)
                if not value:
                    continue
                # A validator may narrow the match (a name list cut at the first
                # non-name). Locate the returned value inside the match so the
                # span always equals the value — redaction depends on that.
                g = "v" if "v" in rx.groupindex and m.group("v") is not None else 0
                pos = line.find(value, m.start(g), m.end())
                if pos < 0:
                    continue
                out.append(Finding(category, name, lineno, pos, pos + len(value), value, engine))
    return out

"""The single record every detector emits."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Finding:
    """One sensitive span inside one line of one file.

    `start`/`end` are character offsets within the line. The raw value is kept
    only in memory (for redaction); reports expose `masked` instead.
    """

    category: str          # secret | pii | infra | custom
    rule: str              # e.g. "github-pat", "kr-rrn", "home-path"
    line: int              # 1-based
    start: int
    end: int
    value: str = field(repr=False)
    engine: str = "builtin"
    path: str = ""
    where: str = ""        # location inside a container file, e.g. "word/comments.xml"

    @property
    def masked(self) -> str:
        return mask(self.value)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("value")
        d["masked"] = self.masked
        return d


def mask(value: str) -> str:
    """Show just enough to recognise the kind, never enough to reuse the value."""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    keep = 4 if len(v) >= 16 else 2
    return f"{v[:keep]}…{'*' * 4}({len(v)} chars)"

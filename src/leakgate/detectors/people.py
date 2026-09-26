"""People you know: a names list matched anywhere, including bare prose.

Rule-based name detection needs a cue (a title, a label, a list). The people
who actually leak from a lab's files are a known, finite set — colleagues,
students, collaborators — so matching their names literally catches the
sentence no rule can: `김민준이 어제 결과를 보냈다`.

Korean names match at a Hangul boundary, with an optional space after the
surname (`김 민준`), when followed by a particle, the copula, an honorific or a
title — anything else means the name is only the start of a longer word or of
a different person (`김민준호`, `정민수`). Latin names also match their common
reorderings: `Minjun Kim`, `Kim Minjun`, `Kim, Minjun`, `M. Kim`, `Kim, M.`.
"""
from __future__ import annotations

import re

from leakgate.detectors.base import Rule, scan_rules
from leakgate.finding import Finding

HANGUL = re.compile(r"^[가-힣]{2,5}$")
FOLLOW = (r"(?=[^가-힣]|$|(?:이|가|은|는|을|를|의|와|과|도|만|께|에|한테|랑|로|으로|님|씨|군|양|네|측|쪽"
          r"|입니|였|선배|후배|교수|박사|선생|학생|연구원|팀장|실장|과장|대리|부장|형|누나|언니|오빠))")
# ASCII boundaries on purpose: `\w` counts Hangul, so `J. Roe에게` would not match;
# and `Kim, M.` ends in a dot, where a trailing \b would fail.
LATIN_L, LATIN_R = r"(?<![A-Za-z0-9.])", r"(?![A-Za-z0-9])"


def _latin_variants(name: str) -> list[str]:
    parts = name.split()
    if len(parts) < 2:
        return [name]
    first, last = " ".join(parts[:-1]), parts[-1]
    initial = parts[0][0]
    return [name, f"{last} {first}", f"{last}, {first}", f"{initial}. {last}", f"{last}, {initial}."]


def build_rules(names: list[str]) -> list[Rule]:
    korean, latin = set(), set()
    for raw in names:
        n = " ".join(raw.split())
        if HANGUL.match(n):
            korean.add(re.escape(n[0]) + r"\s?" + re.escape(n[1:]))
        elif n:
            latin.update(_latin_variants(n))
    rules: list[Rule] = []
    if korean:
        alt = "|".join(sorted(korean, key=len, reverse=True))
        rules.append(("known-person", re.compile(rf"(?<![가-힣])(?:{alt}){FOLLOW}"), None))
    if latin:
        alt = "|".join(sorted((re.escape(v) for v in latin), key=len, reverse=True))
        rules.append(("known-person", re.compile(rf"(?i){LATIN_L}(?:{alt}){LATIN_R}"), None))
    return rules


class PeopleDetector:
    name = "people"

    def __init__(self, names=()):
        self.rules = build_rules([n for n in names if n.strip()])

    def scan(self, text: str) -> list[Finding]:
        return scan_rules(text, self.rules, "pii") if self.rules else []

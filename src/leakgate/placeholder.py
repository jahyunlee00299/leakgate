"""Decide whether a matched credential-looking value is documentation filler.

Over-blocking gets a scanner switched off, and a switched-off scanner catches
nothing — so telling `sk-ant-xxxxxxxx` or `your-api-key-here` apart from a real
key matters as much as the patterns themselves. The rule is strict in one
direction: a value is a placeholder only if EVERY word in it is filler. One
opaque fragment anywhere (`my-project1-a83f2c9d`) makes it real.
"""
from __future__ import annotations

import math
import re
from collections import Counter

FILLER_WORDS = frozenset({
    "your", "yours", "yourkey", "yourapikey", "my", "mykey",
    "api", "key", "keys", "apikey", "token", "secret", "password", "pass", "here",
    "example", "examples", "placeholder", "changeme", "dummy", "fake", "redacted",
    "test", "sample", "replace", "insert", "todo", "none", "null", "value",
    "xxx", "xxxx", "abc", "abcdef", "foo", "bar", "baz", "qux", "demo",
})
# Substrings that mark a whole match as code/documentation, not a literal value.
CODE_MARKERS = ("...", "<", ">", "${", "$(", "{{", "os.environ", "getenv", "process.env",
                "env(", "secrets.", "vault:", "[redacted", "***")
# Well-known published example credentials (vendor docs).
DOC_EXAMPLES = frozenset({
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
})
VENDOR_PREFIX = re.compile(
    r"^(?:sk-(?:ant-(?:api\d+-)?|or-v\d+-|proj-)?|sk_(?:live|test)_|ghp_|gho_|ghs_|github_pat_"
    r"|glpat-|xox[baprs]-|hf_|ntn_|secret_|AKIA|AIza|SG\.)", re.IGNORECASE)
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _is_filler(word: str) -> bool:
    w = word.lower()
    if w in FILLER_WORDS:
        return True
    if w.isdigit() and len(w) <= 4:          # key1, v2 — a LONG digit run is a credential
        return True
    if len(set(w)) == 1:                      # xxxxxxxx, 00000000, ********
        return True
    return False


def is_placeholder(value: str, context: str = "") -> bool:
    """True if `value` is documentation filler rather than a real secret."""
    v = value.strip().strip("\"'`")
    if not v:
        return True
    if v in DOC_EXAMPLES or "EXAMPLE" in v:
        return True
    low = (context or v).lower()
    if any(mk in low for mk in CODE_MARKERS) and not _has_opaque_run(v):
        return True
    # `api_key = OPENAI_API_KEY`, `PASSWORD=REPLACE_ME_BEFORE_DEPLOY` — a
    # SCREAMING_SNAKE name made only of letter words is an identifier or an
    # instruction, not a value. A digit anywhere keeps it suspect.
    if ENV_NAME.match(v) and all(seg.isalpha() for seg in v.split("_") if seg):
        return True
    body = VENDOR_PREFIX.sub("", v)
    if not body:
        return True
    words = [w for w in re.split(r"[-_./\s:]+", body) if w]
    if not words or all(_is_filler(w) for w in words):
        return True
    # Very low character diversity for its length (e.g. 'aaaaaaaabbbbbbbb').
    if len(body) >= 12 and len(set(body)) <= 3:
        return True
    return False


def _has_opaque_run(v: str) -> bool:
    """A 20+ char run with real entropy survives even inside code-looking text."""
    for run in re.findall(r"[A-Za-z0-9_\-+/=]{20,}", v):
        # Real keys carry digits; `environ/OPENAI_API_KEY` does not.
        if sum(c.isdigit() for c in run) >= 2 and shannon_entropy(run) >= 3.5 and not _is_filler(run):
            return True
    return False

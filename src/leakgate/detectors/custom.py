"""Organisation-specific dictionary: the part no generic scanner can know.

Unpublished project names, internal codenames, private repo names — and
sensitive *numbers*: a metric word followed closely by a figure
(`MPSP was $2.31/kg`, `yield of 88.3%`). The metric rule only fires on the
words the user lists, so ordinary technical numbers (`0.2 mM NADH`) stay clean.
Nothing private is hard-coded here; all terms come from the config file.
"""
from __future__ import annotations

import re

from leakgate.detectors.base import Rule, scan_rules
from leakgate.finding import Finding

NUMBER = r"[$€£₩]?\s?\d[\d,]*(?:\.\d+)?\s?(?:%|[A-Za-z$/]+(?:/[A-Za-z]+)?)?"


def build_rules(terms: list[str], patterns: list[str], metrics: list[str],
                metric_window: int = 40) -> list[Rule]:
    rules: list[Rule] = []
    if terms:
        alt = "|".join(sorted((re.escape(t) for t in terms), key=len, reverse=True))
        rules.append(("custom-term", re.compile(rf"(?i)(?<![\w-])(?:{alt})(?![\w])"), None))
    for i, p in enumerate(patterns):
        rules.append((f"custom-pattern-{i + 1}", re.compile(p), None))
    if metrics:
        alt = "|".join(sorted((re.escape(t) for t in metrics), key=len, reverse=True))
        rules.append(("custom-metric-value", re.compile(
            rf"(?i)(?<![\w])(?:{alt})(?![\w])[^\n\d$€£₩]{{0,{metric_window}}}(?P<v>{NUMBER})"), None))
    return rules


class CustomDictionaryDetector:
    name = "custom"

    def __init__(self, terms=(), patterns=(), metrics=(), metric_window: int = 40):
        self.rules = build_rules(list(terms), list(patterns), list(metrics), metric_window)

    def scan(self, text: str) -> list[Finding]:
        return scan_rules(text, self.rules, "custom") if self.rules else []

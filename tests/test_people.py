"""Known-people dictionary. All names are fictional."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from leakgate import config as cfgmod  # noqa: E402
from leakgate.config import Config  # noqa: E402
from leakgate.scanner import Scanner  # noqa: E402

NAMES = ["김민준", "정민", "남궁서연", "Minjun Kim", "Jane Q Roe"]


def values(text: str, names=NAMES) -> list[str]:
    return [f.value for f in Scanner(Config(names=names)).scan_text(text) if f.rule == "known-person"]


@pytest.mark.parametrize("text,expected", [
    ("김민준이 어제 결과를 보냈다", ["김민준"]),          # bare prose, particle
    ("담당은 김민준이다", ["김민준"]),                     # copula
    ("김 민준 선배에게 물어봐", ["김 민준"]),               # spaced surname
    ("남궁서연께서 승인", ["남궁서연"]),                   # compound surname
    ("정민이가 늦는대", ["정민"]),                         # 2-syllable + particle
    ("회의: 정민, 김민준", ["정민", "김민준"]),
    ("thanks to Minjun Kim for", ["Minjun Kim"]),
    ("Kim, Minjun; Roe, J.", ["Kim, Minjun", "Roe, J."]),
    ("reviewed by M. Kim", ["M. Kim"]),
    ("KIM MINJUN (corresponding)", ["KIM MINJUN"]),
])
def test_catches_known_people(text, expected):
    assert values(text) == expected


@pytest.mark.parametrize("text", [
    "정민수 교수",                 # 정민 inside a longer name
    "공정민감도 분석",             # 정민 inside an ordinary word
    "김민준호 선수",               # a different person whose name starts the same
    "Kimberly Minjunson",
    "Mkim.dev",
])
def test_no_substring_hits(text):
    assert values(text) == []


def test_off_without_names():
    assert values("김민준이 왔다", names=[]) == []


def test_names_files_and_redaction(tmp_path):
    (tmp_path / "people.txt").write_text("# lab\n김민준\n\nJane Q Roe  # collaborator\n", encoding="utf-8")
    (tmp_path / cfgmod.CONFIG_NAME).write_text('[custom]\nnames_files = ["people.txt"]\n', encoding="utf-8")
    cfg = cfgmod.load(search_from=tmp_path)
    assert cfg.names == ["김민준", "Jane Q Roe"]
    from leakgate.redact import redact_text
    text = "김민준이 J. Roe에게 보냄\n"
    out = redact_text(text, Scanner(cfg).scan_text(text))
    assert "김민준" not in out and "Roe" not in out and out.startswith("[PII:known-person]이")


def test_many_names_stay_fast():
    import time
    names = [f"가{chr(0xAC00 + i)}{chr(0xAC00 + i * 7 % 11172)}" for i in range(2000)]
    t = time.perf_counter()
    Scanner(Config(names=names)).scan_text("평범한 문장입니다. " * 5000)
    assert time.perf_counter() - t < 3

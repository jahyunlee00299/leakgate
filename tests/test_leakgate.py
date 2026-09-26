"""Contract tests. Credential-shaped values are generated at runtime so the
repository itself never contains one (and never trips its own scan)."""
from __future__ import annotations

import json
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bench")]

from leakgate.cli import main  # noqa: E402
from leakgate.config import Config  # noqa: E402
from leakgate.redact import UnsafeRedaction, redact_file, redact_text  # noqa: E402
from leakgate.scanner import Scanner  # noqa: E402

rng = random.Random(7)
AN = string.ascii_letters + string.digits


def tok(n, alpha=AN):
    return "".join(rng.choice(alpha) for _ in range(n))


def rules(text, **cfg):
    return {f.rule for f in Scanner(Config(**cfg)).scan_text(text)}


# ---- detection: must catch ------------------------------------------------
@pytest.mark.parametrize("line,rule", [
    (lambda: f"ghp_{tok(36)}", "github-token"),
    (lambda: f"AKIA{tok(16, string.ascii_uppercase + '234567')}", "aws-access-key-id"),
    (lambda: f'password = "{tok(14)}9"', "credential-assignment"),
    (lambda: f"SERVICE_ROLE_KEY={tok(30)}1", "credential-assignment"),
    (lambda: f"앱 비밀번호: {tok(16, string.ascii_uppercase + string.digits)}", "credential-assignment"),
    (lambda: f"https://bot:{tok(12)}@dash.example.org/api", "url-embedded-password"),
    (lambda: f"{rng.randint(10**8, 10**9)}:AA{tok(33)}", "telegram-bot-token"),
    (lambda: "연락처 010-2345-6789", "kr-mobile"),
    (lambda: "김민준 교수님께서 말씀하셨다", "kr-name-title"),
    (lambda: "참석자: 한서연, 오태양, 배기훈", "kr-name-labeled"),
    (lambda: "경기도 성남시 분당구 정자동 178-4번지", "kr-address"),
    (lambda: r"C:\Users\jdoe\proj\run.py", "windows-home-path"),
    (lambda: '{"cwd": "C:\\\\Users\\\\jdoe"}', "windows-home-path"),
    (lambda: "ssh me@100.101.102.103", "private-ipv4"),
    (lambda: "https://contoso-my.sharepoint.com/personal/a_b", "sharepoint-tenant"),
    (lambda: f"docker login -p dckr_pat_{tok(27)}", "docker-hub-token"),
    (lambda: f"AIRTABLE=pat{tok(14)}.{tok(64, '0123456789abcdef')}", "airtable-token"),
    (lambda: f"Authorization: KakaoAK {tok(32, '0123456789abcdef')}", "kakao-api-key"),
    (lambda: f"?serviceKey={tok(40)}%2B{tok(30)}%3D%3D&numOfRows=10", "data-go-kr-service-key"),
    (lambda: "차량번호 12가 3456 주차", "kr-vehicle-plate"),
    (lambda: "서울 34나 5678", "kr-vehicle-plate"),
    (lambda: "123허4567 렌터카", "kr-vehicle-plate"),
    (lambda: "학번: 2019123456", "kr-student-employee-id"),
    (lambda: "Employee ID #A1234567", "kr-student-employee-id"),
    (lambda: "사번: ABC-2019-0457", "kr-student-employee-id"),
    (lambda: f"twine upload dist/* -u __token__ -p pypi-{tok(60, AN + '-_')}", "pypi-token"),
    (lambda: f"https://discord.com/api/webhooks/{rng.randint(10**17, 10**18)}/{tok(68)}", "discord-webhook"),
    (lambda: f"Set-Cookie: sessionid={tok(32)}; Path=/; HttpOnly", "session-cookie"),
])
def test_catches(line, rule):
    assert rule in rules(line())


# ---- detection: must NOT flag --------------------------------------------
@pytest.mark.parametrize("line", [
    'api_key = os.environ["OPENAI_API_KEY"]',
    "OPENAI_API_KEY=<YOUR_API_KEY>",
    "export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx",
    "PASSWORD=REPLACE_ME_BEFORE_DEPLOY",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "token = get_token(session)",
    '"cache_read_input_tokens": 183921',
    "NADH (0.2 mM) was added at t = 0",
    "지도교수님께 여쭤보세요",
    "담당교수에게 제출",
    "예시 IP 대역: 203.0.113.0/24",
    "DNS fallback 8.8.8.8",
    "contact: user@example.com",
    "git@github.com:org/repo.git",
    "/usr/local/bin/python and ~/project/data",
    # false positives found auditing real public repositories
    '"token": "ENV:NOTION_TOKEN"',
    'api_key="your-openai-api-key-here"',
    "AI 에이전트는 신입 연구원입니다",
    "chains to `.git/hooks/pre-commit.local` first",
    "`.claude/settings.local.json` is machine-local",
    # false positives found scanning real PDFs (260926): bare 13-digit ids, digit runs
    "patent 8001011234567, 1999.",
    "1999/A:8001011234567",
    "table 1 234 4539 1488 0343 6467 2345",
    # new 0.2.0 rules: ordinary text that looks close
    "3층 1234호 회의실",
    "12가지 1234개의 샘플",
    "2024년 3월 12일",
    "Kakao Maps SDK v2.1.0",
    "kakao_key = os.environ['KAKAO_REST_KEY']",
    "serviceKey=YOUR_SERVICE_KEY_HERE_REPLACE_WITH_REAL_ONE",
    "학번 입력란은 비워 두세요",
    "patient 12345 was enrolled",
    "Set-Cookie: theme=dark; Path=/",
    "pip install pypi-simple-index",
    "사번 발급 예정 (2024)",
])
def test_ignores(line):
    assert rules(line) == set()


def test_custom_dictionary_is_config_only():
    assert rules("falconose titer 12 g/L") == set()
    got = rules("falconose titer 12 g/L", terms=["falconose"], metrics=["titer"])
    assert {"custom-term", "custom-metric-value"} <= got


def test_known_values_matched_and_never_printed(tmp_path, capsys):
    secret = tok(20)
    (tmp_path / "secrets.json").write_text(json.dumps({"svc": {"api_token": secret}}), encoding="utf-8")
    (tmp_path / "log.txt").write_text(f"echoed {secret} here\n", encoding="utf-8")
    rc = main(["scan", str(tmp_path / "log.txt"), "--known-secrets", str(tmp_path / "secrets.json")])
    out = capsys.readouterr().out
    assert rc == 1 and "known-value" in out and secret not in out


def test_inline_suppression_and_allowlist():
    line = f"ghp_{tok(36)}"
    assert rules(line + "  # leakgate:allow") == set()
    assert rules(line, allow=[r"^ghp_"]) == set()


# ---- redaction safety ------------------------------------------------------
def test_redact_jsonl_stays_parseable(tmp_path):
    p = tmp_path / "t.jsonl"
    rows = [{"content": f"key ghp_{tok(36)} and C:\\Users\\jdoe\\x"}, {"ok": 1}]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    sc = Scanner(Config())
    fs = sc.scan_text(p.read_text(encoding="utf-8"), str(p))
    assert redact_file(p, fs) == len(fs) >= 2
    for line in p.read_text(encoding="utf-8").splitlines():
        json.loads(line)
    assert sc.scan_text(p.read_text(encoding="utf-8")) == []
    assert "<USER>" in p.read_text(encoding="utf-8")


def test_stale_finding_refuses_to_guess():
    fs = Scanner(Config()).scan_text(f"ghp_{tok(36)}")
    with pytest.raises(UnsafeRedaction):
        redact_text("something else entirely here", fs)


def test_binary_never_touched(tmp_path):
    b = tmp_path / "img.png"
    payload = b"\x89PNG\r\n\x1a\n" + f"ghp_{tok(36)}".encode()
    b.write_bytes(payload)
    rc = main(["redact", str(tmp_path), "--apply"])
    assert rc == 0 and b.read_bytes() == payload


def test_backup_is_raw_bytes(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(f"x ghp_{tok(36)}\r\n".encode())
    raw = p.read_bytes()
    assert main(["redact", str(p), "--apply", "--backup"]) == 0
    assert (tmp_path / "a.txt.leakgate.bak").read_bytes() == raw
    assert b"\r\n" in p.read_bytes()        # line endings preserved


# ---- CLI contract ------------------------------------------------------------
def test_exit_codes(tmp_path):
    clean = tmp_path / "c.txt"
    clean.write_text("nothing here\n", encoding="utf-8")
    assert main(["scan", str(clean)]) == 0
    clean.write_text(f"ghp_{tok(36)}\n", encoding="utf-8")
    assert main(["scan", str(clean)]) == 1


def test_missing_engine_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    (tmp_path / "x.txt").write_text("hi\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["scan", str(tmp_path / "x.txt"), "--engine", "gitleaks"])
    assert main(["scan", str(tmp_path / "x.txt"), "--engine", "gitleaks", "--allow-missing-engines"]) == 0


def test_sarif_is_valid_json(tmp_path, capsys):
    p = tmp_path / "s.txt"
    p.write_text(f"ghp_{tok(36)}\n", encoding="utf-8")
    main(["scan", str(p), "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["runs"][0]["results"][0]["ruleId"] == "github-token"


def test_long_line_is_linear():
    import time
    t = time.perf_counter()
    Scanner(Config()).scan_text("A1-" * 20000 + "\n" + "token_" * 8000)
    assert time.perf_counter() - t < 2.0


# ---- benchmark regression floor (dev set the rules were written against) -----
def test_dev_corpus_floor():
    import corpus
    cfg = Config(terms=["falconose", "project-falcon-core"], patterns=[r"\bZqXDH\b", r"\bv?(?:Vmax|Km)?,?QRS\b"],
                 metrics=["MPSP", "yield", "titer"])
    sc = Scanner(cfg)
    missed = [s for c, s, l in corpus.corpus() if c != "NEG" and not sc.scan_text(l)]
    fps = [l for c, s, l in corpus.corpus() if c == "NEG" and sc.scan_text(l)]
    assert missed == [] and fps == []


def test_repository_scans_clean():
    """Dogfood: the published tree must pass its own gate."""
    r = subprocess.run([sys.executable, "-m", "leakgate", "scan", str(ROOT / "src"), str(ROOT / "README.md"),
                        str(ROOT / "docs")], capture_output=True, text=True, encoding="utf-8",
                       env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")})
    assert r.returncode == 0, r.stdout[-2000:]

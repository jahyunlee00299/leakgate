"""Synthetic labelled corpus for the benchmark.

Every secret is generated at runtime from a seeded RNG (format-valid, never a
real credential), so no credential-shaped literal is ever committed. Research
terms and organisation names are fictional. Categories: SECRET, KR_PII, INFRA,
RESEARCH (organisation-specific; requires bench/leakgate-bench.toml), NEG.
"""
from __future__ import annotations

import json
import random
import string

rng = random.Random(260924)


def rs(n, alpha=string.ascii_letters + string.digits):
    return "".join(rng.choice(alpha) for _ in range(n))


UP = string.ascii_uppercase + string.digits
B32 = string.ascii_uppercase + "234567"   # real AWS key IDs are base32
HEX = "0123456789abcdef"
B64 = string.ascii_letters + string.digits + "-_"


def rrn():
    while True:
        y, m, d = rng.randint(60, 99), rng.randint(1, 12), rng.randint(1, 28)
        s = f"{y:02d}{m:02d}{d:02d}{rng.choice('12')}{rng.randint(0, 99999):05d}"
        w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
        c = (11 - sum(int(a) * b for a, b in zip(s, w)) % 11) % 10
        return f"{s[:6]}-{s[6:]}{c}"


def luhn(prefix, n=16):
    body = prefix + "".join(rng.choice(string.digits) for _ in range(n - len(prefix) - 1))
    tot = 0
    for i, ch in enumerate(reversed(body)):
        v = int(ch)
        if i % 2 == 0:
            v *= 2
            v -= 9 if v > 9 else 0
        tot += v
    d = (10 - tot % 10) % 10
    s = body + str(d)
    return "-".join(s[i:i + 4] for i in range(0, 16, 4))


def jwt():
    import base64
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": rs(8), "iat": 1726000000}).encode()).decode().rstrip("=")
    return f"{h}.{p}.{rs(43, B64)}"


def corpus():
    C = []
    add = lambda cat, sub, line: C.append((cat, sub, line))
    # ---- SECRET -------------------------------------------------------
    add("SECRET", "anthropic", f'export ANTHROPIC_API_KEY=sk-ant-api03-{rs(93, B64)}AA')
    add("SECRET", "anthropic-jsonl", json.dumps({"type": "tool_result", "content": f"key is sk-ant-api03-{rs(93, B64)}AA ok"}))
    add("SECRET", "openai-proj", f'client = OpenAI(api_key="sk-proj-{rs(48, B64)}")')
    add("SECRET", "openrouter", f'OPENROUTER_API_KEY=sk-or-v1-{rs(64, HEX)}')
    add("SECRET", "github-pat", f'git clone https://ghp_{rs(36)}@github.com/org/repo.git')
    add("SECRET", "github-finegrained", f'token: github_pat_{rs(22)}_{rs(59)}')
    add("SECRET", "aws-akid", f'aws_access_key_id = AKIA{rs(16, B32)}')
    add("SECRET", "aws-secret", f'aws_secret_access_key = {rs(40, string.ascii_letters + string.digits + "/+")}')
    add("SECRET", "slack-bot", f'SLACK_TOKEN="xoxb-{rng.randint(10**11, 10**12)}-{rng.randint(10**12, 10**13)}-{rs(24)}"')
    add("SECRET", "google-api", f'maps_key = "AIza{rs(35, B64)}"')
    add("SECRET", "stripe-live", f'stripe.api_key = "sk_live_{rs(24)}"')
    add("SECRET", "notion", f'NOTION_TOKEN=ntn_{rs(46)}')
    add("SECRET", "telegram-bot", f'bot = Bot("{rng.randint(10**9, 10**10)}:AA{rs(33, B64)}")')
    add("SECRET", "huggingface", f'HF_TOKEN=hf_{rs(34)}')
    add("SECRET", "jwt", f'Authorization: Bearer {jwt()}')
    add("SECRET", "pem-escaped", json.dumps({"out": f"-----BEGIN RSA PRIVATE KEY-----\nMIIEpA{rs(60, B64)}\n-----END RSA PRIVATE KEY-----"}))
    add("SECRET", "db-url", f'DATABASE_URL=postgres://admin:{rs(16)}@db.internal.example:5432/prod')
    add("SECRET", "generic-password", f'password = "{rs(18, string.ascii_letters + string.digits + "!@#")}"')
    add("SECRET", "generic-apikey", f'api_key: "{rs(32, HEX)}"')
    add("SECRET", "app-password-kr", f'네이버웍스 앱 비밀번호: {rs(16, string.ascii_uppercase + string.digits)}')
    add("SECRET", "gitlab", f'GITLAB_TOKEN=glpat-{rs(20, B64)}')
    add("SECRET", "sendgrid", f'SG.{rs(22, B64)}.{rs(43, B64)}')
    # ---- KR_PII -------------------------------------------------------
    add("KR_PII", "rrn", f'주민등록번호: {rrn()}')
    add("KR_PII", "rrn-bare", f'신청인 {rrn()} 확인 완료')
    add("KR_PII", "mobile-dash", f'연락처 010-{rng.randint(1000, 9999)}-{rng.randint(1000, 9999)}')
    add("KR_PII", "mobile-nodash", f'phone=010{rng.randint(10**7, 10**8 - 1)}')
    add("KR_PII", "email-kr", f'문의는 minsu.kim{rng.randint(1, 99)}@univ.ac.kr 로 주세요')
    add("KR_PII", "email-naver", f'"from": "sjpark{rng.randint(100, 999)}@naver.com"')
    add("KR_PII", "name-title", '김민수 교수님께 보고드렸습니다')
    add("KR_PII", "name-plain", '실험 담당: 박서연, 검토: 이도윤')
    add("KR_PII", "bank-account", f'입금계좌 국민은행 {rng.randint(100000, 999999)}-01-{rng.randint(100000, 999999)}')
    add("KR_PII", "address", '주소: 서울특별시 종로구 세종대로 110, 301호')
    add("KR_PII", "card", f'카드번호 {luhn("4")}')
    add("KR_PII", "passport", f'여권번호 M{rng.randint(10**7, 10**8 - 1)}')
    add("KR_PII", "brn", f'사업자등록번호 {rng.randint(100, 999)}-{rng.randint(10, 99)}-{rng.randint(10000, 99999)}')
    add("KR_PII", "name-en", 'Corresponding author: Minsu Kim (minsu@univ.ac.kr)')
    # ---- INFRA --------------------------------------------------------
    add("INFRA", "win-home", r'Traceback: File "C:\Users\jdoe\projects\fit\run.py", line 12')
    add("INFRA", "win-home-fwd", 'cd /c/Users/jdoe/projects/scripts && python fit.py')
    add("INFRA", "posix-home", 'open("/home/alice/data/raw_plate3.csv")')
    add("INFRA", "mac-home", 'saved to /Users/bob/Desktop/out.png')
    add("INFRA", "tailscale-ip", f'ssh home@100.{rng.randint(64, 127)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}')
    add("INFRA", "onedrive", r'D:\OneDrive - Example University\저장소\rawdata\HPLC_0912.xlsx')
    add("INFRA", "private-ip", 'server listening on 192.168.0.23:8080')
    add("INFRA", "json-path", json.dumps({"cwd": "C:\\Users\\jdoe", "file": "C:\\Users\\jdoe\\.claude\\settings.json"}))
    # ---- RESEARCH (org-specific dictionary; only configurable tools can hit)
    add("RESEARCH", "enzyme", 'ZqXDH activity dropped after 4 h at 30 °C')
    add("RESEARCH", "ratelaw", 'vQRS = Vmax,QRS * S / (Km,QRS + S)')
    add("RESEARCH", "substrate", 'final falconose titer was higher than expected')
    add("RESEARCH", "repo", 'see project-falcon-core/analysis/tea.py')
    add("RESEARCH", "figure", 'MPSP was $2.31/kg in the base case')
    add("RESEARCH", "yield", 'overall yield of 88.3% after crystallization')
    # ---- NEG (must NOT be flagged) ------------------------------------
    for line in [
        'api_key = os.environ["OPENAI_API_KEY"]',
        'OPENAI_API_KEY=<YOUR_API_KEY>',
        'export ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx',
        'password: ${DB_PASSWORD}',
        'token = get_token(session)',
        'api_key = "your-api-key-here"',
        'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
        f'commit {rs(40, HEX)}',
        f'sha256: {rs(64, HEX)}',
        f'"uuid": "{rs(8, HEX)}-{rs(4, HEX)}-4{rs(3, HEX)}-a{rs(3, HEX)}-{rs(12, HEX)}"',
        f'"tool_use_id": "toolu_01{rs(22)}"',
        f'"requestId": "req_011C{rs(20)}"',
        'kcat/Km = 1.2e5 M^-1 s^-1 for the generic example',
        'NADH (0.2 mM) was added at t = 0',
        'Python 3.11.4 and numpy 2.1.0 are required',
        'DOI: 10.1021/acscatal.3c01234',
        'DNS fallback 8.8.8.8',
        '지도교수님께 여쭤보세요',
        '담당교수에게 제출',
        'Run date 2026-09-24 10:32:11',
        'See Figure S3 and Table 2',
        'ISBN 978-89-7914-123-4',
        'contact: user@example.com',
        'Cat# 1234-5678, lot 22A',
        'D-galactose was used as the substrate in the textbook example',
        'https://github.com/gitleaks/gitleaks',
        'base_url = "https://api.anthropic.com/v1/messages"',
        'model = "claude-opus-5-5"',
        'secret_scan_guard.sh blocked the command',
        '주민등록번호 앞 6자리만 입력하세요',
        'ORCID 0000-0002-1825-0097',
        'accession NC_000913.3',
        'primer F: ATGCGTACGTTAGCCTAGGCTAACGTAGCTAGCTAG',
        '"cache_read_input_tokens": 183921',
        'Km,app was 12 mM in the generic tutorial',
        'The weather in Seoul is nice today.',
        'localhost:9000 tunnel',
        'image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
        'git@github.com:org/repo.git',
        'hash = hashlib.md5(b"abc").hexdigest()',
    ]:
        add("NEG", "neg", line)
    return C

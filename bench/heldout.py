"""NOTE: first blind set. Its misses were then used to fix general rule gaps,
so it is no longer blind — bench/heldout2.py carries the unbiased numbers.

Held-out test corpus for the leakgate sensitive-data scanner.

This module is intentionally written WITHOUT looking at the detector source
(`src/`) or the existing training corpus (`bench/corpus.py`). It exists to
catch rules that were overfit to the visible corpus.

All "secret-looking" literals are synthesized at import/call time from a
seeded PRNG (`random.Random(SEED)`) in the correct vendor format/length, so
no realistic credential ever appears as a literal in this source file. All
Korean PII with a checksum (주민등록번호, 사업자등록번호, 카드번호) is
generated with the checksum computed correctly. No real person's data is
used anywhere; all names are invented.

`corpus()` returns a list of (category, subtype, line) triples where
category in {"SECRET", "KR_PII", "INFRA", "NEG"}.
"""

from __future__ import annotations

import random
import string

SEED = 20260924

# ---------------------------------------------------------------------------
# low-level random helpers
# ---------------------------------------------------------------------------

_ALNUM = string.ascii_letters + string.digits
_HEX = string.hexdigits[:16]
_B64 = string.ascii_letters + string.digits + "+/"
_B64URL = string.ascii_letters + string.digits + "-_"


def _rand_str(rng: random.Random, n: int, alphabet: str = _ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _rand_digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def _rand_hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _rand_upper(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(n))


def _rand_b64(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_B64) for _ in range(n))


# ---------------------------------------------------------------------------
# checksum-correct Korean PII generators
# ---------------------------------------------------------------------------


def _rrn(rng: random.Random, decade: str = "20") -> str:
    """Generate a checksum-valid 주민등록번호 (post-2020 random-tail style)."""
    yy = rng.randint(0, 25)
    mm = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    front = f"{yy:02d}{mm:02d}{dd:02d}"
    gender = rng.choice(["3", "4"]) if decade == "20" else rng.choice(["1", "2"])
    # post-2020 issuance: remaining 6 digits (incl. check digit) are random,
    # no embedded region/sequence code -> we still compute a valid checksum.
    serial5 = _rand_digits(rng, 5)
    digits12 = front + gender + serial5
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(d) * w for d, w in zip(digits12, weights))
    check = (11 - (total % 11)) % 10
    return f"{front}-{gender}{serial5}{check}"


def _arn(rng: random.Random) -> str:
    """외국인등록번호 - same 13-digit shape, gender code 5-8, checksum computed
    with the same weighted-sum rule used for RRNs (format-correct)."""
    yy = rng.randint(70, 99)
    mm = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    front = f"{yy:02d}{mm:02d}{dd:02d}"
    gender = rng.choice(["5", "6", "7", "8"])
    serial5 = _rand_digits(rng, 5)
    digits12 = front + gender + serial5
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(d) * w for d, w in zip(digits12, weights))
    check = (11 - (total % 11)) % 10
    return f"{front}-{gender}{serial5}{check}"


def _brn(rng: random.Random) -> str:
    """사업자등록번호 (business registration number) with valid checksum."""
    office = _rand_digits(rng, 3)
    kind = _rand_digits(rng, 2)
    serial = _rand_digits(rng, 4)
    digits9 = office + kind + serial
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(int(d) * w for d, w in zip(digits9, weights))
    s += (int(digits9[8]) * 5) // 10
    check = (10 - s % 10) % 10
    return f"{office}-{kind}-{serial}{check}"


def _luhn_check(digits: str) -> int:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def _card_number(rng: random.Random, prefix: str) -> str:
    body = prefix + _rand_digits(rng, 15 - len(prefix))
    check = _luhn_check(body)
    full = body + str(check)
    return "-".join(full[i : i + 4] for i in range(0, 16, 4))


def _driver_license(rng: random.Random) -> str:
    region = f"{rng.randint(11, 28):02d}"
    year = f"{rng.randint(0, 25):02d}"
    serial = _rand_digits(rng, 6)
    check = _rand_digits(rng, 2)
    return f"{region}-{year}-{serial}-{check}"


def _passport(rng: random.Random) -> str:
    return rng.choice("MRSD") + _rand_digits(rng, 8)


def _account_no(rng: random.Random, bank: str, pattern: list[int]) -> str:
    parts = [_rand_digits(rng, n) for n in pattern]
    return f"{bank} " + "-".join(parts)


def _phone_mobile(rng: random.Random, sep: str = "-") -> str:
    mid = _rand_digits(rng, 4)
    tail = _rand_digits(rng, 4)
    return f"010{sep}{mid}{sep}{tail}"


def _phone_landline(rng: random.Random, area: str) -> str:
    mid = _rand_digits(rng, 3)
    tail = _rand_digits(rng, 4)
    return f"{area}-{mid}-{tail}"


# ---------------------------------------------------------------------------
# secret literal generators (vendor-format-correct, never hardcoded)
# ---------------------------------------------------------------------------


def _anthropic_key(rng: random.Random) -> str:
    return "sk-ant-api03-" + _rand_str(rng, 93, _ALNUM + "-_") + "-AA"


def _openai_key(rng: random.Random) -> str:
    return "sk-proj-" + _rand_str(rng, 48, _ALNUM)


def _github_pat_classic(rng: random.Random) -> str:
    return "ghp_" + _rand_str(rng, 36, _ALNUM)


def _github_pat_fine_grained(rng: random.Random) -> str:
    return "github_pat_" + _rand_str(rng, 22, _ALNUM) + "_" + _rand_str(rng, 59, _ALNUM)


def _github_app_token(rng: random.Random) -> str:
    return "ghs_" + _rand_str(rng, 36, _ALNUM)


def _gitlab_pat(rng: random.Random) -> str:
    return "glpat-" + _rand_str(rng, 20, _ALNUM + "-_")


def _slack_bot_token(rng: random.Random) -> str:
    return f"xoxb-{_rand_digits(rng, 13)}-{_rand_digits(rng, 13)}-{_rand_str(rng, 24, _ALNUM)}"


def _slack_user_token(rng: random.Random) -> str:
    return f"xoxp-{_rand_digits(rng, 13)}-{_rand_digits(rng, 13)}-{_rand_digits(rng, 13)}-{_rand_hex(rng, 32)}"


def _slack_webhook(rng: random.Random) -> str:
    return (
        "https://hooks.slack.com/services/"
        f"T{_rand_str(rng, 8, string.ascii_uppercase + string.digits)}/"
        f"B{_rand_str(rng, 8, string.ascii_uppercase + string.digits)}/"
        f"{_rand_str(rng, 24, _ALNUM)}"
    )


def _aws_access_key_id(rng: random.Random) -> str:
    return "AKIA" + _rand_str(rng, 16, string.ascii_uppercase + string.digits)


def _aws_secret_key(rng: random.Random) -> str:
    return _rand_b64(rng, 40)


def _gcp_private_key_field(rng: random.Random) -> str:
    body = "\\n".join(_rand_b64(rng, 64) for _ in range(6))
    return (
        '"private_key": "-----BEGIN PRIVATE KEY-----\\n'
        + body
        + '\\n-----END PRIVATE KEY-----\\n"'
    )


def _azure_conn_str(rng: random.Random) -> str:
    account = "st" + _rand_str(rng, 10, string.ascii_lowercase + string.digits)
    key = _rand_b64(rng, 88) + "=="
    return (
        f"DefaultEndpointsProtocol=https;AccountName={account};"
        f"AccountKey={key};EndpointSuffix=core.windows.net"
    )


def _stripe_key(rng: random.Random) -> str:
    return "sk_live_" + _rand_str(rng, 24, _ALNUM)


def _twilio_sid_and_token(rng: random.Random) -> tuple[str, str]:
    return "AC" + _rand_hex(rng, 32), _rand_hex(rng, 32)


def _sendgrid_key(rng: random.Random) -> str:
    return "SG." + _rand_str(rng, 22, _ALNUM + "-_") + "." + _rand_str(rng, 43, _ALNUM + "-_")


def _mailgun_key(rng: random.Random) -> str:
    return "key-" + _rand_hex(rng, 32)


def _discord_bot_token(rng: random.Random) -> str:
    part1 = _rand_str(rng, 24, _ALNUM)
    part2 = _rand_str(rng, 6, _ALNUM)
    part3 = _rand_str(rng, 27, _ALNUM + "-_")
    return f"{part1}.{part2}.{part3}"


def _telegram_bot_token(rng: random.Random) -> str:
    return f"{_rand_digits(rng, 10)}:{_rand_str(rng, 35, _ALNUM + '-_')}"


def _npm_token(rng: random.Random) -> str:
    return "npm_" + _rand_str(rng, 36, _ALNUM)


def _pypi_token(rng: random.Random) -> str:
    return "pypi-AgEIcHlwaS5vcmc" + _rand_str(rng, 60, _B64URL)


def _hf_token(rng: random.Random) -> str:
    return "hf_" + _rand_str(rng, 34, _ALNUM)


def _notion_token(rng: random.Random) -> str:
    return "secret_" + _rand_str(rng, 43, _ALNUM)


def _fake_jwt(rng: random.Random) -> str:
    header = _rand_b64(rng, 20).rstrip("=")
    payload = _rand_b64(rng, 80).rstrip("=")
    sig = _rand_b64(rng, 43).rstrip("=")
    return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.{sig}"


def _generic_password(rng: random.Random, n: int = 14) -> str:
    return _rand_str(rng, n, _ALNUM + "!@#$%^&*")


def _ssh_pem_header_escaped(rng: random.Random) -> str:
    body = "\\n".join(_rand_b64(rng, 64) for _ in range(4))
    return '"key": "-----BEGIN RSA PRIVATE KEY-----\\n' + body + '\\n-----END RSA PRIVATE KEY-----\\n"'


def _tailscale_ip(rng: random.Random) -> str:
    return f"100.{rng.randint(64, 127)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _private_ip(rng: random.Random, kind: str) -> str:
    if kind == "10":
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if kind == "172":
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


# ---------------------------------------------------------------------------
# corpus assembly
# ---------------------------------------------------------------------------


def corpus() -> list[tuple[str, str, str]]:
    rng = random.Random(SEED)
    rows: list[tuple[str, str, str]] = []

    def add(cat: str, sub: str, line: str) -> None:
        rows.append((cat, sub, line))

    # ------------------------------------------------------------------ #
    # SECRET (~35)
    # ------------------------------------------------------------------ #
    add("SECRET", "anthropic_api_key", f'ANTHROPIC_API_KEY={_anthropic_key(rng)}')
    add("SECRET", "anthropic_api_key", f'  "authorization": "Bearer {_anthropic_key(rng)}"')
    add("SECRET", "openai_api_key", f'OPENAI_API_KEY="{_openai_key(rng)}"')
    add("SECRET", "openai_api_key", f"curl https://api.openai.com/v1/chat/completions -H 'Authorization: Bearer {_openai_key(rng)}'")
    add("SECRET", "github_pat_classic", f'git remote set-url origin https://{_github_pat_classic(rng)}@github.com/jmin-lab/private-repo.git')
    add("SECRET", "github_pat_fine_grained", f'GITHUB_TOKEN={_github_pat_fine_grained(rng)}')
    add("SECRET", "github_app_token", f'  "token": "{_github_app_token(rng)}"')
    add("SECRET", "gitlab_pat", f'GITLAB_TOKEN={_gitlab_pat(rng)}')
    add("SECRET", "slack_bot_token", f'SLACK_BOT_TOKEN={_slack_bot_token(rng)}')
    add("SECRET", "slack_user_token", f'legacy_token = "{_slack_user_token(rng)}"')
    add("SECRET", "slack_webhook", f'SLACK_WEBHOOK_URL={_slack_webhook(rng)}')
    aws_id = _aws_access_key_id(rng)
    aws_secret = _aws_secret_key(rng)
    add("SECRET", "aws_access_key_id", f'aws_access_key_id = {aws_id}')
    add("SECRET", "aws_secret_access_key", f'aws_secret_access_key = {aws_secret}')
    add("SECRET", "gcp_service_account", _gcp_private_key_field(rng))
    add("SECRET", "azure_storage_conn_str", f'AZURE_STORAGE_CONNECTION_STRING="{_azure_conn_str(rng)}"')
    add("SECRET", "stripe_key", f'STRIPE_SECRET_KEY={_stripe_key(rng)}')
    tw_sid, tw_token = _twilio_sid_and_token(rng)
    add("SECRET", "twilio", f'TWILIO_ACCOUNT_SID={tw_sid}\nTWILIO_AUTH_TOKEN={tw_token}')
    add("SECRET", "sendgrid_key", f'SENDGRID_API_KEY={_sendgrid_key(rng)}')
    add("SECRET", "mailgun_key", f'MAILGUN_API_KEY={_mailgun_key(rng)}')
    add("SECRET", "discord_bot_token", f'client.login("{_discord_bot_token(rng)}")')
    add("SECRET", "telegram_bot_token", f'TELEGRAM_BOT_TOKEN={_telegram_bot_token(rng)}')
    add("SECRET", "npm_token", f'//registry.npmjs.org/:_authToken={_npm_token(rng)}')
    add("SECRET", "pypi_token", f'password = {_pypi_token(rng)}')
    add("SECRET", "huggingface_token", f'HF_TOKEN={_hf_token(rng)}')
    add("SECRET", "notion_token", f'NOTION_TOKEN={_notion_token(rng)}')
    add("SECRET", "supabase_jwt", f'SUPABASE_SERVICE_ROLE_KEY={_fake_jwt(rng)}')
    add("SECRET", "yaml_password", f'database:\n  user: labuser\n  password: {_generic_password(rng)}')
    add("SECRET", "env_password", f'DB_PASSWORD={_generic_password(rng, 12)}')
    add("SECRET", "ini_password", f'[auth]\npassword = {_generic_password(rng, 10)}')
    add("SECRET", "db_uri_password", f'postgres://labadmin:{_generic_password(rng, 16)}@db-prod.internal:5432/labdb')
    add("SECRET", "db_uri_password", f'mongodb+srv://svc_ingest:{_generic_password(rng, 18)}@cluster0.mongodb.net/records')
    add("SECRET", "basic_auth_url", f'https://reportbot:{_generic_password(rng, 12)}@internal-dash.example.local/api')
    add("SECRET", "ssh_pem_json_escaped", '{"deploy_key": ' + _ssh_pem_header_escaped(rng) + '}')
    add("SECRET", "korean_password_label", f'비밀번호: {_generic_password(rng, 10)}')
    add("SECRET", "korean_api_key_label", f'API 키 = {_anthropic_key(rng)[:40]}')
    add("SECRET", "python_hardcoded", f'client = APIClient(api_key="{_openai_key(rng)}")')
    add("SECRET", "transcript_tool_output", '{"tool": "bash", "output": "export GH_TOKEN=' + _github_pat_classic(rng) + '\\n"}')

    # ------------------------------------------------------------------ #
    # KR_PII (~30)
    # ------------------------------------------------------------------ #
    add("KR_PII", "rrn", f'주민등록번호: {_rrn(rng)}')
    add("KR_PII", "rrn", f'주민번호 {_rrn(rng, decade="19")} 확인 부탁드립니다.')
    add("KR_PII", "rrn_no_sep", f'주민등록번호(-없이): {_rrn(rng).replace("-", "")}')
    add("KR_PII", "arn", f'외국인등록번호: {_arn(rng)}')
    add("KR_PII", "mobile", f'연락처: {_phone_mobile(rng)}')
    add("KR_PII", "mobile_dot", f'휴대폰 {_phone_mobile(rng, sep=".")} 로 문자 주세요.')
    add("KR_PII", "mobile_nosep", f'전화번호: {_phone_mobile(rng).replace("-", "")}')
    add("KR_PII", "mobile_intl", f'+82 10-{_rand_digits(rng, 4)}-{_rand_digits(rng, 4)} (국제발신)')
    add("KR_PII", "landline", f'사무실: {_phone_landline(rng, "02")}')
    add("KR_PII", "landline", f'대표전화 {_phone_landline(rng, "031")}')
    add("KR_PII", "email_naver", 'lab_assistant_kim@naver.com 로 자료 보내드렸습니다.')
    add("KR_PII", "email_daum", 'sunhwa.jang77@daum.net')
    add("KR_PII", "email_univ", '작성자 이메일: minsoo.kang@yonsei.ac.kr')
    add("KR_PII", "email_company", '담당자 이메일: y.chae@fabrikam-pharma.co.kr')
    add("KR_PII", "name_title", '김민준 교수님께서 회의 일정을 변경하셨습니다.')
    add("KR_PII", "name_title", '이수현 박사님 검토 요청드립니다.')
    add("KR_PII", "name_label", '작성자: 박지훈')
    add("KR_PII", "name_label", '담당자: 최유진 (내선 214)')
    add("KR_PII", "name_label", '수신: 정다은 선생님')
    add("KR_PII", "name_list", '참석자 목록: 한서연, 오태양, 배기훈')
    add("KR_PII", "name_running_text", '오늘 회의는 강도윤 씨가 주재했습니다.')
    add("KR_PII", "account_no", _account_no(rng, "국민은행", [6, 2, 6]))
    add("KR_PII", "account_no", _account_no(rng, "신한은행", [3, 3, 6]))
    add("KR_PII", "card_number", f'카드번호 {_card_number(rng, "4")}')
    add("KR_PII", "card_number", f'법인카드: {_card_number(rng, "51")}')
    add("KR_PII", "passport", f'여권번호: {_passport(rng)}')
    add("KR_PII", "driver_license", f'운전면허번호 {_driver_license(rng)}')
    add("KR_PII", "brn", f'사업자등록번호: {_brn(rng)}')
    add("KR_PII", "address_road", '서울특별시 강남구 테헤란로 152, 8층 (역삼동)')
    add("KR_PII", "address_jibun", '경기도 성남시 분당구 정자동 178-4번지')
    add("KR_PII", "dob_name", '홍서준 (1990.03.15 생)')
    add("KR_PII", "en_name_email", 'John Carter <j.carter@examplecorp.com>')
    add("KR_PII", "en_name_email", 'Contact: Sarah Mitchell (sarah.mitchell@nordicresearch.no)')

    # ------------------------------------------------------------------ #
    # INFRA (~15)
    # ------------------------------------------------------------------ #
    add("INFRA", "win_path", r'C:\Users\jmin.kwon\Documents\lab_notebook\raw_data.xlsx')
    add("INFRA", "win_path_escaped", '{"cwd": "C:\\\\Users\\\\jmin.kwon\\\\projects\\\\enzyme-model"}')
    add("INFRA", "gitbash_path", '/c/Users/jmin.kwon/scratch/fit_v3.py')
    add("INFRA", "linux_home", '/home/jmin/workspace/pipeline/run.sh')
    add("INFRA", "macos_home", '/Users/jmin.kwon/Library/Application Support/Code/logs')
    add("INFRA", "wsl_path", '/mnt/c/Users/jmin.kwon/OneDrive - Contoso University/data')
    add("INFRA", "onedrive_tenant", r'C:\Users\jmin.kwon\OneDrive - Contoso University\Desktop\report.docx')
    add("INFRA", "sharepoint_url", 'https://contosou-my.sharepoint.com/personal/jmin_kwon_contoso_edu/Documents/lab')
    add("INFRA", "private_ip_10", f'DB host: {_private_ip(rng, "10")}')
    add("INFRA", "private_ip_172", f'internal_gateway = "{_private_ip(rng, "172")}"')
    add("INFRA", "private_ip_192", f'printer at {_private_ip(rng, "192")}')
    add("INFRA", "tailscale_ip", f'ssh jmin@{_tailscale_ip(rng)}  # laptop over tailscale')
    add("INFRA", "internal_hostname", 'ssh jmin.kwon@labserver01.internal "tail -f /var/log/pipeline.log"')
    add("INFRA", "internal_hostname", 'scp results.csv jmin.kwon@build-node-03.corp.local:/data/out/')
    add("INFRA", "win_path", r'C:\Users\yuna.oh\AppData\Roaming\claude\config.json')

    # ------------------------------------------------------------------ #
    # NEG (~60) — must NOT be flagged
    # ------------------------------------------------------------------ #
    add("NEG", "placeholder", 'ANTHROPIC_API_KEY=<YOUR_API_KEY_HERE>')
    add("NEG", "placeholder", 'OPENAI_API_KEY=sk-...')
    add("NEG", "placeholder", 'token = "xxxxxxxxxxxxxxxxxxxxxxxx"')
    add("NEG", "placeholder", 'API_KEY=${SECRET_API_KEY}')
    add("NEG", "placeholder", 'api_key = os.getenv("OPENAI_API_KEY")')
    add("NEG", "placeholder", 'password: "your-password-here"')
    add("NEG", "placeholder", 'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  # example only, replace me')
    add("NEG", "doc_example_aws", 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE')
    add("NEG", "doc_example_aws", 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    add("NEG", "git_sha", 'commit 4f2a9c1e8b3d5a67f0912cde34ab56789fa01234')
    add("NEG", "git_sha_short", 'Merge pull request #482 from jmin/fix-retry (a1b2c3d)')
    add("NEG", "uuid", 'request_id: 550e8400-e29b-41d4-a716-446655440000')
    add("NEG", "uuid", 'session_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8"')
    add("NEG", "hash", 'sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    add("NEG", "hash", 'md5sum data.tar.gz -> d41d8cd98f00b204e9800998ecf8427e')
    add("NEG", "base64_image", 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=')
    add("NEG", "tool_call_id", 'toolu_01A2B3C4D5E6F7G8H9J0K1L2M3')
    add("NEG", "version_string", 'leakgate==2.4.1 (build 20260901)')
    add("NEG", "version_string", 'Python 3.11.9 / pip 24.0')
    add("NEG", "doi", 'https://doi.org/10.1021/acscatal.3c04521')
    add("NEG", "orcid", 'ORCID: 0000-0002-1825-0097')
    add("NEG", "isbn", 'ISBN 978-3-16-148410-0')
    add("NEG", "date", '실험은 2024년 3월 15일에 진행되었습니다.')
    add("NEG", "time", '회의는 오늘 12시 30분에 시작합니다.')
    add("NEG", "public_ip", 'DNS resolves to 8.8.8.8 and 1.1.1.1')
    add("NEG", "localhost", 'server running at http://127.0.0.1:8000/docs')
    add("NEG", "localhost", 'redis://localhost:6379/0')
    add("NEG", "chem_kinetics", 'kcat = 42.7 /s, Km = 2.3 mM for the wild-type enzyme')
    add("NEG", "chem_kinetics", 'k_cat/K_m = 1.2e5 M^-1 s^-1 at pH 7.4')
    add("NEG", "chem_reagent", 'NADH consumption monitored at OD340; OD600 reached 0.8 after 6 h')
    add("NEG", "chem_conc", '기질 농도는 3.5 g/L로 유지했습니다.')
    add("NEG", "gene_name", 'The gapA gene encodes glyceraldehyde-3-phosphate dehydrogenase.')
    add("NEG", "protein_name", 'Purified His-tagged AlkB variant eluted at 250 mM imidazole.')
    add("NEG", "kr_title_no_person", '지도교수님께 진행 상황을 보고하세요.')
    add("NEG", "kr_title_no_person", '담당자에게 문의 바랍니다.')
    add("NEG", "kr_title_no_person", '다음 주 교수회의 안건을 정리해 주세요.')
    add("NEG", "kr_title_no_person", '박사과정 학생들은 세미나에 참석 바랍니다.')
    add("NEG", "kr_title_no_person", '선생님들께 안내 문자를 발송했습니다.')
    add("NEG", "catalog_lot", 'Cat# 15596026, Lot 2847193, Sigma-Aldrich')
    add("NEG", "catalog_lot", '시약 주문번호 88-1234-5678 (재고 확인용)')
    add("NEG", "public_github_url", 'See https://github.com/pytorch/pytorch/issues/98765 for details.')
    add("NEG", "example_email", 'Send feedback to support@example.com')
    add("NEG", "example_email", 'test.user@example.org')
    add("NEG", "git_ssh_url", 'git remote add origin git@github.com:openai/gym.git')
    add("NEG", "path_no_username", 'binary installed at /usr/local/bin/ffmpeg')
    add("NEG", "path_no_username", r'installer default path: C:\Program Files\Anaconda3')
    add("NEG", "path_no_username", 'load data from ./data/raw.csv')
    add("NEG", "path_no_username", 'config lives under ~/project/config.yaml')
    add("NEG", "password_policy_text", '비밀번호는 8자 이상, 특수문자를 포함해야 합니다.')
    add("NEG", "password_policy_text", 'Passwords must be rotated every 90 days per IT policy.')
    add("NEG", "config_var_name", 'PASSWORD_MIN_LENGTH = 8')
    add("NEG", "config_var_name", 'MAX_TOKEN_LENGTH = 4096')
    add("NEG", "token_count", '"usage": {"input_tokens": 1532, "output_tokens": 284}')
    add("NEG", "token_count", 'total tokens used this session: 84213')
    add("NEG", "secret_english_word", "Keep this changelog entry secret until the release goes out.")
    add("NEG", "secret_english_word", 'The function has no secret side effects and is pure.')
    add("NEG", "public_institution", '국세청 홈택스 고객센터: 126 (내선 없음, 공용 대표번호)')
    add("NEG", "generic_id_number", 'Build ID: 20260924.1847-release')
    add("NEG", "generic_id_number", 'Invoice No. INV-2026-000482 (template, no amount)')
    add("NEG", "public_ip_range_doc", '예시 IP 대역: 203.0.113.0/24 (TEST-NET-3, RFC 5737)')
    add("NEG", "kr_sentence_number", '이번 배치 수율은 92.3%로 확인되었습니다.')
    add("NEG", "kr_sentence_number", '샘플 5개를 3반복으로 측정했습니다.')
    add("NEG", "enzyme_unit", '효소 활성은 1 U/mg protein으로 정규화했습니다.')
    add("NEG", "placeholder_password_field", 'password: "changeme"')
    add("NEG", "placeholder_password_field", 'PASSWORD=REPLACE_ME_BEFORE_DEPLOY')

    return rows


def _print_summary(rows: list[tuple[str, str, str]]) -> None:
    counts: dict[str, int] = {}
    for cat, _sub, _line in rows:
        counts[cat] = counts.get(cat, 0) + 1
    total = len(rows)
    print(f"heldout corpus: {total} lines total")
    for cat in sorted(counts):
        print(f"  {cat}: {counts[cat]}")


if __name__ == "__main__":
    _print_summary(corpus())

"""Blind held-out benchmark corpus (set 3) for the leakgate sensitive-data scanner.

This file was written BLIND: without reading the detector's source code, its
test suite, its README, or any other benchmark set in this repository. It was
composed purely from general knowledge of what real secrets, Korean personal
data, and internal infrastructure references look like in the wild (config
files, logs, chat exports, manuscripts, code). Written 2026-09-26.

This is the corpus the leakgate 0.2.0 benchmark numbers are computed from. Any
future change to detector rules should be scored against an INDEPENDENT new
blind set, not by re-reading or tuning against this one.

Categories:
    SECRET  - credentials/tokens/keys/connection strings (global + Korean vendors)
    KR_PII  - Korean personal data (RRN, phone, card, bank, names, addresses, ...)
    INFRA   - local usernames in paths, internal hosts/IPs, cloud tenant names
    NEG     - hard negatives: realistic non-sensitive lines a naive scanner over-flags

All credential-shaped values and checksummed identifiers (resident registration
numbers, business registration numbers, card numbers) are generated AT CALL TIME
from a single seeded random.Random(SEED) instance - there are no literal secret
strings anywhere in this source file. Every person, organisation, hostname, and
tenant name below is invented (Contoso/Fabrikam/Northwind-style placeholders, or
invented Korean names); none refer to a real university, company, or person.
"""

from __future__ import annotations

import random
import string

SEED = 748219  # fixed for reproducibility of the 0.2.0 benchmark numbers; not a date

# ---------------------------------------------------------------------------
# Invented reference data (fictional; no real people, orgs, or hosts)
# ---------------------------------------------------------------------------

LAST_NAMES_KO = ["김", "이", "박", "최", "정", "강", "조", "윤", "임", "한", "오", "신", "배", "권", "문", "서"]
FIRST_NAMES_KO = [
    "민준", "서연", "도윤", "지우", "하은", "태윤", "은서", "서준", "하윤", "지호",
    "수아", "동혁", "유진", "나윤", "성민", "지안", "서현", "준서", "예은", "시우",
]
ROMANIZED_NAMES = [
    "Kim Min-jun", "Lee Seo-yeon", "Park Do-yoon", "Choi Ji-woo", "Jung Ha-eun",
    "Han Ji-ho", "Yoon Seo-jun", "Bae Yu-jin", "Kang Tae-yang", "Oh Su-a",
    "Shin Dong-hyuk", "Kwon Na-yoon",
]
FICTIONAL_ORGS = [
    "Contoso Biotech Korea", "Fabrikam Pharma", "Northwind Labs", "Tailspin Diagnostics",
    "Woodgrove Institute", "Litware Research Center", "한빛제약", "새봄바이오연구소",
    "청람생명과학", "해오름메디컬",
]
INTERNAL_DOMAINS = ["contoso.local", "fabrikam.corp", "northwind.io", "tailspin.com", "woodgrove.local"]
CLOUD_TENANTS = [
    "contoso.sharepoint.com", "fabrikam.onmicrosoft.com", "OneDrive - Fabrikam Corporation",
    "OneDrive - Contoso Biotech Korea", "northwind.sharepoint.com",
]
LOCAL_USERNAMES = ["alice.kim", "msjeon", "jpark", "dyoon", "hyunwoo", "skim42", "yuna.lee", "tommy.oh"]
ADDRESS_STREETS = [
    ("서울특별시 강남구 테헤란로", "그린빌"),
    ("경기도 성남시 분당구 판교로 256번길", "오크우드"),
    ("부산광역시 해운대구 마린시티 2로", "오션타워"),
    ("대전광역시 유성구 대학로", "하늘채"),
    ("인천광역시 연수구 송도과학로", "그레이스빌"),
]


def _random_ko_name(rng: random.Random) -> str:
    return rng.choice(LAST_NAMES_KO) + rng.choice(FIRST_NAMES_KO)


# ---------------------------------------------------------------------------
# Low-level random string / checksum helpers
# ---------------------------------------------------------------------------

def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def _alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def _lower_alnum(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _hexstr(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _b64ish(rng: random.Random, n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "+/"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _urlsafe(rng: random.Random, n: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alphabet) for _ in range(n))


def _luhn_check_digit(partial_digits: list[int]) -> int:
    """Standard Luhn check digit for the digits that will precede it."""
    total = 0
    for i, d in enumerate(reversed(partial_digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def _luhn_number(rng: random.Random, total_len: int, prefix: str = "") -> str:
    body = [int(c) for c in prefix]
    while len(body) < total_len - 1:
        body.append(rng.randint(0, 9))
    check = _luhn_check_digit(body)
    return "".join(str(d) for d in body) + str(check)


def _rrn_check_digit(twelve: list[int]) -> int:
    """Korean resident-registration-number checksum over the first 12 digits."""
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(d * w for d, w in zip(twelve, weights))
    return (11 - (total % 11)) % 10


def _brn_check_digit(nine: list[int]) -> int:
    """Korean business-registration-number checksum over the first 9 digits."""
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(d * w for d, w in zip(nine, weights))
    total += (nine[8] * 5) // 10
    return (10 - total % 10) % 10


# ---------------------------------------------------------------------------
# KR_PII value generators
# ---------------------------------------------------------------------------

def _rrn_valid(rng: random.Random) -> str:
    """Pre-2020-style RRN with a correctly computed checksum digit."""
    yy = rng.randint(50, 99)
    mm = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    g = rng.choice([1, 2])
    serial = [rng.randint(0, 9) for _ in range(5)]
    twelve = [int(c) for c in f"{yy:02d}{mm:02d}{dd:02d}"] + [g] + serial
    check = _rrn_check_digit(twelve)
    return f"{yy:02d}{mm:02d}{dd:02d}-{g}{''.join(map(str, serial))}{check}"


def _rrn_invalid(rng: random.Random) -> str:
    """Post-2020-dated RRN shape with a random (not checksum-valid) last digit."""
    yy = rng.randint(0, 24)
    mm = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    g = rng.choice([3, 4])
    tail = [rng.randint(0, 9) for _ in range(6)]
    return f"{yy:02d}{mm:02d}{dd:02d}-{g}{''.join(map(str, tail))}"


def _brn(rng: random.Random) -> str:
    area = rng.randint(100, 999)
    kind = rng.randint(10, 99)
    nine = [int(c) for c in f"{area:03d}{kind:02d}"] + [rng.randint(0, 9) for _ in range(4)]
    check = _brn_check_digit(nine)
    body = "".join(map(str, nine))
    return f"{body[0:3]}-{body[3:5]}-{body[5:9]}{check}"


def _phone_mobile(rng: random.Random) -> str:
    return f"010-{_digits(rng, 4)}-{_digits(rng, 4)}"


def _phone_landline(rng: random.Random) -> str:
    area = rng.choice(["02", "031", "051", "053", "042", "062"])
    if area == "02":
        mid_len = rng.choice([3, 4])
        return f"02-{_digits(rng, mid_len)}-{_digits(rng, 4)}"
    return f"{area}-{_digits(rng, 3)}-{_digits(rng, 4)}"


def _card_number(rng: random.Random) -> str:
    prefix = rng.choice(["4", "51", "9410", "5678", "3542"])
    num = _luhn_number(rng, 16, prefix)
    return "-".join(num[i:i + 4] for i in range(0, 16, 4))


def _bank_account(rng: random.Random) -> str:
    bank = rng.choice(["신한", "국민", "우리", "하나", "농협", "카카오뱅크"])
    fmt = rng.choice([0, 1, 2])
    if fmt == 0:
        acct = f"{_digits(rng, 3)}-{_digits(rng, 2)}-{_digits(rng, 6)}"
    elif fmt == 1:
        acct = f"{_digits(rng, 3)}-{_digits(rng, 6)}-{_digits(rng, 2)}"
    else:
        acct = f"{_digits(rng, 4)}-{_digits(rng, 4)}-{_digits(rng, 4)}-{_digits(rng, 2)}"
    return f"{bank}은행 {acct}"


def _passport(rng: random.Random) -> str:
    letter = rng.choice("MSRD")
    return f"{letter}{_digits(rng, 8)}"


def _driver_license(rng: random.Random) -> str:
    region = rng.randint(11, 29)
    return f"{region:02d}-{rng.randint(1, 99):02d}-{_digits(rng, 6)}-{rng.randint(10, 99):02d}"


def _vehicle_plate(rng: random.Random) -> str:
    syll = rng.choice(["가", "나", "다", "라", "마", "바", "사", "아", "자", "하"])
    if rng.random() < 0.5:
        return f"{rng.randint(100, 999)}{syll}{_digits(rng, 4)}"
    region = rng.choice(["서울", "부산", "대구", "인천", "경기"])
    return f"{region}{rng.randint(10, 99)}{syll}{_digits(rng, 4)}"


def _student_id(rng: random.Random) -> str:
    return f"{rng.randint(2018, 2024)}{_digits(rng, 6)}"


def _employee_id(rng: random.Random) -> str:
    return f"EMP-{rng.randint(2018, 2024)}-{_digits(rng, 4)}"


def _health_insurance(rng: random.Random) -> str:
    g = rng.choice([1, 2])
    return f"{g}-{_digits(rng, 10)}"


def _birth_date(rng: random.Random) -> str:
    y = rng.randint(1960, 2005)
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    return f"{y}년 {m}월 {d}일생"


def _address(rng: random.Random) -> str:
    street, complex_name = rng.choice(ADDRESS_STREETS)
    num = rng.randint(1, 300)
    dong = rng.randint(1, 20)
    ho = rng.randint(101, 2004)
    return f"{street} {num}, {complex_name} {dong}동 {ho}호"


# ---------------------------------------------------------------------------
# KR_PII line factories (one sensitive item per line, realistic context)
# ---------------------------------------------------------------------------

def _rrn_valid_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name} ({_rrn_valid(rng)}) 님 본인 확인이 완료되었습니다."


def _rrn_invalid_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"임시 등록: {name}, 주민등록번호 {_rrn_invalid(rng)} (검토 필요)"


def _phone_mobile_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님 연락처: {_phone_mobile(rng)}"


def _phone_landline_line(rng: random.Random) -> str:
    org = rng.choice(FICTIONAL_ORGS)
    return f"{org} 대표전화 {_phone_landline(rng)} 로 문의 바랍니다."


def _email_personal_line(rng: random.Random) -> str:
    user = rng.choice(["minjun.kim", "seoyeon.lee", "doyoon.park", "jiwoo.choi", "haeun.jung"])
    domain = rng.choice(["naver.com", "daum.net", "gmail.com", "kakao.com"])
    return f"개인 이메일: {user}{rng.randint(1, 99)}@{domain}"


def _card_line(rng: random.Random) -> str:
    name = rng.choice(ROMANIZED_NAMES)
    return f"Card on file for {name}: {_card_number(rng)} (exp {rng.randint(1, 12):02d}/{rng.randint(26, 30)})"


def _bank_account_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님 환불 계좌: {_bank_account(rng)}"


def _passport_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님 여권번호: {_passport(rng)}"


def _driver_license_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님 운전면허번호: {_driver_license(rng)}"


def _address_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님 배송지: {_address(rng)}"


def _birth_date_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님은 {_birth_date(rng)}."


def _vehicle_plate_line(rng: random.Random) -> str:
    return f"방문 예정 차량 번호판: {_vehicle_plate(rng)}"


def _student_id_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name} 학생 학번: {_student_id(rng)}"


def _employee_id_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name} 사번: {_employee_id(rng)}"


def _business_reg_line(rng: random.Random) -> str:
    org = rng.choice(FICTIONAL_ORGS)
    return f"{org}의 사업자등록번호는 {_brn(rng)} 입니다."


def _health_insurance_line(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    return f"{name}님의 건강보험증 번호는 {_health_insurance(rng)} 입니다."


def _name_bare_prose(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    templates = [
        f"{name} 씨가 어제 실험실에 다녀갔습니다.",
        f"다음 회의는 {name}님이 주관하기로 했습니다.",
        f"{name}에게 시약 주문을 부탁드렸어요.",
        f"어제 {name}이(가) 데이터를 정리해서 보냈습니다.",
        f"{name} 학생이 이번 학기 인턴으로 합류했습니다.",
        f"{name} 연구원이 샘플을 냉장고에 보관해두었습니다.",
    ]
    return rng.choice(templates)


def _name_messenger(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    hour = rng.randint(1, 11)
    minute = rng.randint(0, 59)
    ampm = rng.choice(["오전", "오후"])
    templates = [
        f"[{name}] [{ampm} {hour}:{minute:02d}] 내일 미팅 몇 시에 하나요?",
        f"[{name}] [{ampm} {hour}:{minute:02d}] 샘플 결과 공유드립니다.",
        f"[{name}] [{ampm} {hour}:{minute:02d}] 오늘 실험 끝나고 연락드릴게요.",
        f"[{name}] [{ampm} {hour}:{minute:02d}] 자료 확인 부탁드립니다!",
    ]
    return rng.choice(templates)


def _name_author_line(rng: random.Random) -> str:
    n = rng.randint(2, 4)
    authors = [_random_ko_name(rng) for _ in range(n)]
    year = rng.randint(2018, 2024)
    org = rng.choice(FICTIONAL_ORGS)
    return f"{', '.join(authors)} et al. ({year}). Enzymatic cascade optimization. {org} Technical Report."


def _name_romanized(rng: random.Random) -> str:
    name = rng.choice(ROMANIZED_NAMES)
    templates = [
        f"Corresponding author: {name}, Department of Biotechnology.",
        f"{name} presented the preliminary kinetic data during the seminar.",
        f"Please cc {name} on the reagent order confirmation.",
        f"Reviewer 2 recommended contacting {name} for the raw dataset.",
    ]
    return rng.choice(templates)


# ---------------------------------------------------------------------------
# INFRA line factories
# ---------------------------------------------------------------------------

def _username_path(rng: random.Random) -> str:
    user = rng.choice(LOCAL_USERNAMES)
    templates = [
        f"C:\\Users\\{user}\\Documents\\project\\config.yaml",
        f"/home/{user}/workspace/reports/summary.csv",
        f"/Users/{user}/Library/Application Support/app/cache.db",
        f"\\\\wsl$\\Ubuntu\\home\\{user}\\logs\\error.log",
        f'{{"path": "C:\\\\Users\\\\{user}\\\\AppData\\\\Local\\\\Temp\\\\build.log"}}',
    ]
    return rng.choice(templates)


def _hostname_internal(rng: random.Random) -> str:
    host = rng.choice(["db01", "prod-web03", "cache-redis02", "auth-svc01", "build-agent04"])
    domain = rng.choice(INTERNAL_DOMAINS)
    port = rng.choice([5432, 3306, 6379, 8443])
    return f"Connecting to {host}.internal.{domain} on port {port}"


def _private_ip(rng: random.Random) -> str:
    kind = rng.choice(["10", "172", "192"])
    if kind == "10":
        ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    elif kind == "172":
        ip = f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    else:
        ip = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    port = rng.choice([22, 443, 8080, 9200])
    return f"internal host reachable at {ip}:{port}"


def _cloud_tenant(rng: random.Random) -> str:
    tenant = rng.choice(CLOUD_TENANTS)
    templates = [
        f"파일 위치: {tenant}/sites/Research/Shared Documents/rawdata.xlsx",
        f"Sync source: {tenant}",
        f"Azure AD tenant app registered under {tenant}",
    ]
    return rng.choice(templates)


def _internal_url(rng: random.Random) -> str:
    host = rng.choice(["jenkins", "git", "grafana", "confluence", "vpn"])
    domain = rng.choice(INTERNAL_DOMAINS)
    return f"http://{host}.internal.{domain}:8080/job/deploy-pipeline/lastBuild/console"


# ---------------------------------------------------------------------------
# SECRET line factories
# ---------------------------------------------------------------------------

def _aws_access_key(rng: random.Random) -> str:
    key = "AKIA" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    return f"AWS_ACCESS_KEY_ID={key}"


def _aws_secret_key(rng: random.Random) -> str:
    return f"AWS_SECRET_ACCESS_KEY={_b64ish(rng, 40)}"


def _gcp_api_key(rng: random.Random) -> str:
    key = "AIza" + _alnum(rng, 35)
    return f'google_api_key: "{key}"  # maps embed config'


def _github_pat(rng: random.Random) -> str:
    key = "ghp_" + _alnum(rng, 36)
    return f"remote: https://{key}@github.com/contoso-biotech/private-repo.git"


def _slack_bot_token(rng: random.Random) -> str:
    key = f"xoxb-{_digits(rng, 12)}-{_digits(rng, 13)}-{_alnum(rng, 24)}"
    return f"[{rng.choice(ROMANIZED_NAMES)}] slack token 공유합니다: {key}"


def _slack_webhook(rng: random.Random) -> str:
    url = f"https://hooks.slack.com/services/T{_alnum(rng, 8).upper()}/B{_alnum(rng, 8).upper()}/{_alnum(rng, 24)}"
    return f"SLACK_WEBHOOK_URL={url}"


def _stripe_secret(rng: random.Random) -> str:
    key = "sk_live_" + _alnum(rng, 24)
    return f'stripe.api_key = "{key}"'


def _sendgrid_key(rng: random.Random) -> str:
    key = f"SG.{_urlsafe(rng, 22)}.{_urlsafe(rng, 43)}"
    return f"SENDGRID_API_KEY={key}"


def _npm_token(rng: random.Random) -> str:
    key = "npm_" + _alnum(rng, 36)
    return f"//registry.npmjs.org/:_authToken={key}"


def _pypi_token(rng: random.Random) -> str:
    key = "pypi-AgENd" + _alnum(rng, 40)
    return f"twine upload --username __token__ --password {key} dist/*"


def _azure_conn_string(rng: random.Random) -> str:
    acct = rng.choice(["contosostorage", "fabrikamdata01"])
    key = _b64ish(rng, 86) + "=="
    return f"DefaultEndpointsProtocol=https;AccountName={acct};AccountKey={key};EndpointSuffix=core.windows.net"


def _mongodb_uri(rng: random.Random) -> str:
    user = rng.choice(["appuser", "svc_reader"])
    pw = _alnum(rng, 14)
    cluster = _lower_alnum(rng, 5)
    return f"mongodb+srv://{user}:{pw}@cluster0-{cluster}.mongodb.net/proddb?retryWrites=true"


def _postgres_uri(rng: random.Random) -> str:
    user = rng.choice(["appuser", "dbadmin"])
    pw = _alnum(rng, 12)
    ip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"DATABASE_URL=postgresql://{user}:{pw}@{ip}:5432/proddb"


def _generic_db_password(rng: random.Random) -> str:
    return f"DB_PASSWORD={_alnum(rng, 14)}"


def _ssh_private_key(rng: random.Random) -> str:
    chunk = _b64ish(rng, 64)
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\\n{chunk}...  (id_rsa 첨부 내용 일부)"


def _bearer_token_log(rng: random.Random) -> str:
    token = _urlsafe(rng, 40)
    return f'10.0.4.12 - - [26/Sep/2026:14:22:01] "GET /api/v1/status HTTP/1.1" 200 Authorization: Bearer {token}'


def _naver_cloud_key(rng: random.Random) -> str:
    access = "NCP" + _alnum(rng, 20).upper()
    secret = _alnum(rng, 40)
    return f"ncloud.accessKey={access}; ncloud.secretKey={secret}"


def _kakao_rest_key(rng: random.Random) -> str:
    key = _hexstr(rng, 32)
    return f'KAKAO_REST_API_KEY = "{key}"  // build.gradle local override'


def _toss_payments_secret(rng: random.Random) -> str:
    key = rng.choice(["live_sk_", "test_sk_"]) + _alnum(rng, 24)
    return f"TOSS_SECRET_KEY={key}"


def _basic_auth_url(rng: random.Random) -> str:
    user = rng.choice(["admin", "svc-monitor"])
    pw = _alnum(rng, 10)
    return f"curl -u {user}:{pw} https://internal-api.contoso.local/v1/status"


def _jwt_token(rng: random.Random) -> str:
    header = _urlsafe(rng, 20)
    payload = _urlsafe(rng, 40)
    sig = _urlsafe(rng, 43)
    return f"Set-Cookie: session={header}.{payload}.{sig}; Path=/; HttpOnly"


def _discord_webhook(rng: random.Random) -> str:
    return f"https://discord.com/api/webhooks/{_digits(rng, 18)}/{_alnum(rng, 68)}"


def _openai_style_key(rng: random.Random) -> str:
    key = "sk-" + _alnum(rng, 48)
    return f"OPENAI_API_KEY={key}"


def _google_service_account_json(rng: random.Random) -> str:
    chunk = _b64ish(rng, 60)
    return f'"private_key": "-----BEGIN PRIVATE KEY-----\\n{chunk}\\n-----END PRIVATE KEY-----\\n"'


def _korean_messenger_password(rng: random.Random) -> str:
    name = _random_ko_name(rng)
    pw = _alnum(rng, 10)
    hour = rng.randint(1, 11)
    minute = rng.randint(0, 59)
    ampm = rng.choice(["오전", "오후"])
    return f"[{name}] [{ampm} {hour}:{minute:02d}] 서버 비번 {pw} 로 바꿨어요, 공유드립니다."


# ---------------------------------------------------------------------------
# NEG (hard negative) line factories
# ---------------------------------------------------------------------------

def _concentration(rng: random.Random) -> str:
    conc = rng.choice([10, 20, 50, 100, 150, 200])
    unit = rng.choice(["mM", "\u00b5M", "mg/mL", "% (v/v)"])
    reagent = rng.choice(["Tris-HCl", "NaCl", "MgCl2", "glucose", "glycerol", "imidazole"])
    ph = rng.choice([6.8, 7.0, 7.4, 8.0])
    return f"{conc} {unit} {reagent} 완충액 (pH {ph}) 조건에서 반응을 진행했다."


def _reaction_date(rng: random.Random) -> str:
    y = rng.randint(2019, 2026)
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    return f"{y}년 {m}월 {d}일 실험을 진행하였다."


def _catalog_number(rng: random.Random) -> str:
    vendor = rng.choice(["Sigma-Aldrich", "Thermo Fisher", "Merck", "TCI", "Takara"])
    cat = rng.randint(1000, 99999)
    return f"{vendor} Cat# T{cat} 시약을 사용하였다."


def _doi(rng: random.Random) -> str:
    a = rng.randint(10, 99)
    b = rng.randint(1000, 9999)
    c = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    return f"https://doi.org/10.{a}{b}/{c}"


def _patent_number(rng: random.Random) -> str:
    country = rng.choice(["US", "KR", "EP"])
    num = rng.randint(1000000, 9999999)
    return f"{country} Patent No. {num} B1 관련 선행기술을 검토하였다."


def _isbn(rng: random.Random) -> str:
    return f"ISBN 978-{rng.randint(0, 9)}-{rng.randint(100, 999)}-{rng.randint(10000, 99999)}-{rng.randint(0, 9)}"


def _sample_id(rng: random.Random) -> str:
    return f"Sample ID: RX-{rng.randint(2019, 2026)}-{rng.randint(1000, 9999)}"


def _room_number(rng: random.Random) -> str:
    building = rng.choice(["공학관", "자연과학관", "산학협력관"])
    room = rng.randint(101, 905)
    return f"다음 회의는 {building} {room}호에서 진행됩니다."


def _page_range(rng: random.Random) -> str:
    a = rng.randint(1, 900)
    b = a + rng.randint(1, 30)
    return f"참고문헌은 pp. {a}-{b}에 수록되어 있다."


def _version_string(rng: random.Random) -> str:
    return f"현재 배포 버전은 v{rng.randint(1, 5)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}-beta 입니다."


def _chemical_formula(rng: random.Random) -> str:
    formula = rng.choice(["C6H12O6", "C2H5OH", "NaHCO3", "C3H8O3", "C6H8O7"])
    return f"생성물의 분자식은 {formula} 으로 확인되었다."


def _git_sha(rng: random.Random) -> str:
    return f"commit {_hexstr(rng, 7)} 에서 버그가 수정되었습니다."


def _uuid_line(rng: random.Random) -> str:
    h = lambda n: _hexstr(rng, n)  # noqa: E731
    return f"작업 ID: {h(8)}-{h(4)}-4{h(3)}-a{h(3)}-{h(12)}"


def _lockfile_hash(rng: random.Random) -> str:
    return (
        '"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", '
        f'"integrity": "sha512-{_b64ish(rng, 64)}=="'
    )


def _placeholder_credential(rng: random.Random) -> str:
    templates = [
        "API_KEY=<YOUR_API_KEY_HERE>",
        "password: xxxx-xxxx-xxxx-xxxx  # 실제 값으로 교체하세요",
        "token = os.environ['GITHUB_TOKEN']",
        "DATABASE_URL=postgres://user:password@localhost:5432/dbname  # example only",
        'client_secret: "<REPLACE_ME>"',
        "# TODO: set SECRET_KEY before deploying",
    ]
    return rng.choice(templates)


def _example_email(rng: random.Random) -> str:
    user = rng.choice(["alice", "bob", "testuser", "admin", "noreply"])
    return f"문의: {user}@example.com 으로 연락 바랍니다."


def _public_ip(rng: random.Random) -> str:
    ip = rng.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"])
    return f"DNS 서버는 {ip} 로 설정되어 있습니다."


def _doc_ip(rng: random.Random) -> str:
    ip = rng.choice(["192.0.2.10", "198.51.100.23", "203.0.113.7"])
    return f"예시 설정에서는 {ip} 를 사용한다 (RFC 5737 문서용 주소)."


def _public_figure_citation(rng: random.Random) -> str:
    templates = [
        "Darwin, C. (1859). On the Origin of Species. John Murray.",
        "Watson, J.D. & Crick, F.H.C. (1953). Nature, 171, 737-738.",
        "Einstein, A. (1905). Annalen der Physik, 17, 891-921.",
        "Curie, M. (1898). Comptes Rendus, 127, 175-178.",
    ]
    return rng.choice(templates)


def _generic_role_no_name(rng: random.Random) -> str:
    templates = [
        "교수님께 문의드리니 다음 주에 답변 주신다고 하셨습니다.",
        "담당자 확인 요망.",
        "선생님께서 자료를 검토해주시기로 했습니다.",
        "팀장님 승인 후 진행 예정입니다.",
        "관리자에게 문의하세요.",
    ]
    return rng.choice(templates)


# ---------------------------------------------------------------------------
# Corpus assembly
# ---------------------------------------------------------------------------

_FACTORIES: list[tuple[str, str, object]] = []


def _add(category: str, subtype: str, fn, times: int = 1) -> None:
    for _ in range(times):
        _FACTORIES.append((category, subtype, fn))


# SECRET (~60)
_add("SECRET", "aws_access_key", _aws_access_key, 2)
_add("SECRET", "aws_secret_key", _aws_secret_key, 2)
_add("SECRET", "gcp_api_key", _gcp_api_key, 2)
_add("SECRET", "github_pat", _github_pat, 4)
_add("SECRET", "slack_bot_token", _slack_bot_token, 2)
_add("SECRET", "slack_webhook", _slack_webhook, 2)
_add("SECRET", "stripe_secret_key", _stripe_secret, 2)
_add("SECRET", "sendgrid_key", _sendgrid_key, 2)
_add("SECRET", "npm_token", _npm_token, 2)
_add("SECRET", "pypi_token", _pypi_token, 2)
_add("SECRET", "azure_storage_conn_string", _azure_conn_string, 2)
_add("SECRET", "mongodb_uri", _mongodb_uri, 3)
_add("SECRET", "postgres_uri", _postgres_uri, 3)
_add("SECRET", "generic_db_password", _generic_db_password, 3)
_add("SECRET", "ssh_private_key", _ssh_private_key, 2)
_add("SECRET", "bearer_token_log", _bearer_token_log, 4)
_add("SECRET", "naver_cloud_key", _naver_cloud_key, 2)
_add("SECRET", "kakao_rest_key", _kakao_rest_key, 2)
_add("SECRET", "toss_payments_secret", _toss_payments_secret, 2)
_add("SECRET", "basic_auth_url", _basic_auth_url, 2)
_add("SECRET", "jwt_token", _jwt_token, 4)
_add("SECRET", "discord_webhook", _discord_webhook, 2)
_add("SECRET", "openai_style_key", _openai_style_key, 2)
_add("SECRET", "google_service_account_json", _google_service_account_json, 2)
_add("SECRET", "korean_messenger_password", _korean_messenger_password, 3)

# KR_PII (~70, roughly a third = name forms)
_add("KR_PII", "rrn_valid", _rrn_valid_line, 6)
_add("KR_PII", "rrn_invalid_post2020", _rrn_invalid_line, 4)
_add("KR_PII", "phone_mobile", _phone_mobile_line, 5)
_add("KR_PII", "phone_landline", _phone_landline_line, 2)
_add("KR_PII", "email_personal", _email_personal_line, 3)
_add("KR_PII", "card_luhn", _card_line, 5)
_add("KR_PII", "bank_account", _bank_account_line, 3)
_add("KR_PII", "passport", _passport_line, 2)
_add("KR_PII", "driver_license", _driver_license_line, 2)
_add("KR_PII", "address", _address_line, 3)
_add("KR_PII", "birth_date", _birth_date_line, 2)
_add("KR_PII", "vehicle_plate", _vehicle_plate_line, 2)
_add("KR_PII", "student_id", _student_id_line, 2)
_add("KR_PII", "employee_id", _employee_id_line, 2)
_add("KR_PII", "business_reg_number", _business_reg_line, 2)
_add("KR_PII", "health_insurance", _health_insurance_line, 2)
_add("KR_PII", "name_bare_prose", _name_bare_prose, 6)
_add("KR_PII", "name_messenger", _name_messenger, 6)
_add("KR_PII", "name_author_line", _name_author_line, 5)
_add("KR_PII", "name_romanized", _name_romanized, 6)

# INFRA (~30)
_add("INFRA", "username_path", _username_path, 8)
_add("INFRA", "hostname_internal", _hostname_internal, 6)
_add("INFRA", "private_ip", _private_ip, 6)
_add("INFRA", "cloud_tenant", _cloud_tenant, 5)
_add("INFRA", "internal_url", _internal_url, 5)

# NEG (~110)
_add("NEG", "concentration", _concentration, 6)
_add("NEG", "reaction_date", _reaction_date, 6)
_add("NEG", "catalog_number", _catalog_number, 6)
_add("NEG", "doi", _doi, 6)
_add("NEG", "patent_number", _patent_number, 5)
_add("NEG", "isbn", _isbn, 5)
_add("NEG", "sample_id", _sample_id, 6)
_add("NEG", "room_number", _room_number, 5)
_add("NEG", "page_range", _page_range, 5)
_add("NEG", "version_string", _version_string, 5)
_add("NEG", "chemical_formula", _chemical_formula, 6)
_add("NEG", "git_sha", _git_sha, 6)
_add("NEG", "uuid", _uuid_line, 6)
_add("NEG", "lockfile_hash", _lockfile_hash, 5)
_add("NEG", "placeholder_credential", _placeholder_credential, 6)
_add("NEG", "example_email", _example_email, 5)
_add("NEG", "public_ip", _public_ip, 5)
_add("NEG", "doc_ip", _doc_ip, 5)
_add("NEG", "public_figure_citation", _public_figure_citation, 6)
_add("NEG", "generic_role_no_name", _generic_role_no_name, 5)


def corpus() -> list[tuple[str, str, str]]:
    """Return the blind heldout3 corpus as (category, subtype, line) tuples.

    Deterministic given SEED: every credential-shaped or checksummed value is
    generated fresh from random.Random(SEED) on each call.
    """
    rng = random.Random(SEED)
    rows: list[tuple[str, str, str]] = []
    for category, subtype, fn in _FACTORIES:
        rows.append((category, subtype, fn(rng)))
    return rows


def _main() -> None:
    rows = corpus()
    counts: dict[str, int] = {}
    for category, _subtype, _line in rows:
        counts[category] = counts.get(category, 0) + 1
    for category in ("SECRET", "KR_PII", "INFRA", "NEG"):
        print(f"{category}: {counts.get(category, 0)}")
    print(f"TOTAL: {len(rows)}")


if __name__ == "__main__":
    _main()

"""Blind held-out test corpus for the leakgate sensitive-data scanner.

Written from general knowledge only, WITHOUT reading the detector sources
or the other benchmark sets (they were never inspected while writing this
module). This is the set the published numbers come from: the rules were
frozen before it was first run.

`corpus()` returns a list of (category, subtype, line) triples where
category is one of SECRET / KR_PII / INFRA / NEG.

All secret-looking values are generated at call time from a fixed RNG seed
(deliberately different from any date-derived seed) so the literal strings
never appear hard-coded in source. Checksummed identifiers (RRN, business
registration number, credit-card Luhn) are computed correctly so they read
as structurally valid instances of their format.

All people, organisations, and hosts are invented (contoso / fabrikam /
example-style placeholders); no real university, company, or tenant name is
used.
"""

from __future__ import annotations

import random
import string

# Fixed seed for reproducibility -- intentionally NOT the "today" date seed.
SEED = 471893

_ALNUM = string.ascii_letters + string.digits
_B64URL = string.ascii_letters + string.digits + "-_"
_HEXCHARS = "0123456789abcdef"


# ---------------------------------------------------------------------------
# small RNG helpers
# ---------------------------------------------------------------------------

def _alnum(rng: random.Random, n: int, charset: str = _ALNUM) -> str:
    return "".join(rng.choice(charset) for _ in range(n))


def _hexs(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_HEXCHARS) for _ in range(n))


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def _b64url(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(_B64URL) for _ in range(n))


def _upper_alnum(rng: random.Random, n: int) -> str:
    return _alnum(rng, n, string.ascii_uppercase + string.digits)


# ---------------------------------------------------------------------------
# checksum helpers (KR_PII)
# ---------------------------------------------------------------------------

def _rrn_check_digit(twelve: str) -> int:
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    s = sum(int(d) * w for d, w in zip(twelve, weights))
    return (11 - (s % 11)) % 10


def make_rrn(rng: random.Random, foreign: bool = False) -> str:
    yy = rng.randint(0, 99)
    mm = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    if foreign:
        g = rng.choice([5, 6, 7, 8])
    else:
        g = rng.choice([1, 2, 3, 4])
    serial = _digits(rng, 5)
    twelve = f"{yy:02d}{mm:02d}{dd:02d}{g}{serial}"
    chk = _rrn_check_digit(twelve)
    return f"{twelve[:6]}-{twelve[6:]}{chk}"


def _brn_check_digit(nine: str) -> int:
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(int(d) * w for d, w in zip(nine, weights))
    s += (int(nine[8]) * 5) // 10
    return (10 - (s % 10)) % 10


def make_brn(rng: random.Random) -> str:
    nine = _digits(rng, 9)
    chk = _brn_check_digit(nine)
    return f"{nine[0:3]}-{nine[3:5]}-{nine[5:9]}{chk}"


def _luhn_check_digit(partial: str) -> int:
    digits = [int(d) for d in partial][::-1]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def make_card(rng: random.Random, prefix: str = "4556") -> str:
    body = prefix + _digits(rng, 11)
    chk = _luhn_check_digit(body)
    full = body + str(chk)
    return f"{full[0:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"


_SURNAMES = ["김", "이", "박", "최", "정", "강", "윤", "임", "한", "서", "오", "신", "조", "배", "권"]
_GIVEN = [
    "민수", "영희", "지훈", "수진", "다은", "태양", "서연", "재현", "소영", "민재",
    "유진", "동혁", "하늘", "지우", "준서", "하은", "성민", "예은", "도윤", "채원",
]


def make_name(rng: random.Random) -> str:
    return rng.choice(_SURNAMES) + rng.choice(_GIVEN)


# ---------------------------------------------------------------------------
# corpus assembly
# ---------------------------------------------------------------------------

def corpus() -> list[tuple[str, str, str]]:
    rng = random.Random(SEED)
    rows: list[tuple[str, str, str]] = []

    def add(cat: str, sub: str, line: str) -> None:
        rows.append((cat, sub, line))

    # =====================================================================
    # SECRET (~40+)
    # =====================================================================

    anthropic_key = "sk-ant-api03-" + _b64url(rng, 93) + "-" + _b64url(rng, 4) + "AA"
    add("SECRET", "anthropic_api_key",
        f'export ANTHROPIC_API_KEY="{anthropic_key}"')

    openai_key = "sk-proj-" + _b64url(rng, 56)
    add("SECRET", "openai_api_key",
        f'OPENAI_API_KEY = "{openai_key}"  # loaded from env in prod normally')

    google_key = "AIzaSy" + _alnum(rng, 33)
    add("SECRET", "google_gemini_key",
        f'curl "https://generativelanguage.googleapis.com/v1/models?key={google_key}"')

    aws_ak = "AKIA" + _upper_alnum(rng, 16)
    add("SECRET", "aws_access_key_id",
        f'aws_access_key_id = {aws_ak}')

    aws_sk = _alnum(rng, 40, _ALNUM + "+/")
    add("SECRET", "aws_secret_access_key",
        f'aws_secret_access_key = {aws_sk}')

    azure_key = _alnum(rng, 88, _ALNUM + "+/") + "=="
    add("SECRET", "azure_storage_conn_string",
        f'AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;'
        f'AccountName=fabrikamstore;AccountKey={azure_key};EndpointSuffix=core.windows.net')

    gcp_key_b64 = "\\n".join(_alnum(rng, 64, _ALNUM + "+/") for _ in range(3))
    add("SECRET", "gcp_service_account_json",
        '{"type": "service_account", "project_id": "fabrikam-prod", '
        f'"private_key": "-----BEGIN PRIVATE KEY-----\\n{gcp_key_b64}==\\n-----END PRIVATE KEY-----\\n", '
        '"client_email": "svc-deploy@fabrikam-prod.iam.gserviceaccount.com"}')

    ghp = "ghp_" + _alnum(rng, 36)
    add("SECRET", "github_pat_classic",
        f'git remote set-url origin https://{ghp}@github.com/contoso/internal-tools.git')

    gh_fine = "github_pat_" + _alnum(rng, 22) + "_" + _alnum(rng, 59)
    add("SECRET", "github_pat_fine_grained",
        f'GITHUB_TOKEN={gh_fine}')

    glpat = "glpat-" + _alnum(rng, 20)
    add("SECRET", "gitlab_pat",
        f'  script:\n    - git clone https://oauth2:{glpat}@gitlab.contoso.net/team/app.git')

    bb_pw = _alnum(rng, 24)
    add("SECRET", "bitbucket_app_password",
        f'bitbucket_app_password: "{bb_pw}"  # generated for CI deploy user')

    slack_tok = "xoxb-" + _digits(rng, 11) + "-" + _digits(rng, 13) + "-" + _alnum(rng, 24)
    add("SECRET", "slack_bot_token",
        f'SLACK_BOT_TOKEN={slack_tok}')

    discord_tok = _b64url(rng, 24) + "." + _b64url(rng, 6) + "." + _b64url(rng, 27)
    add("SECRET", "discord_bot_token",
        f'client.login("{discord_tok}")')

    tg_tok = _digits(rng, 10) + ":" + _alnum(rng, 35)
    add("SECRET", "telegram_bot_token",
        f'curl https://api.telegram.org/bot{tg_tok}/getMe')

    twilio_sid = "AC" + _hexs(rng, 32)
    twilio_auth = _hexs(rng, 32)
    add("SECRET", "twilio_credentials",
        f'client = Client("{twilio_sid}", "{twilio_auth}")')

    sendgrid_key = "SG." + _b64url(rng, 22) + "." + _b64url(rng, 43)
    add("SECRET", "sendgrid_api_key",
        f'SENDGRID_API_KEY={sendgrid_key}')

    mailgun_key = "key-" + _hexs(rng, 32)
    add("SECRET", "mailgun_api_key",
        f'MAILGUN_API_KEY = "{mailgun_key}"')

    stripe_key = "sk_live_" + _alnum(rng, 24)
    add("SECRET", "stripe_secret_key",
        f'stripe.api_key = "{stripe_key}"')

    shopify_key = "shpat_" + _hexs(rng, 32)
    add("SECRET", "shopify_admin_token",
        f'X-Shopify-Access-Token: {shopify_key}')

    datadog_key = _hexs(rng, 32)
    add("SECRET", "datadog_api_key",
        f'DD_API_KEY={datadog_key}')

    sentry_dsn = f'https://{_hexs(rng, 32)}@o{_digits(rng, 6)}.ingest.sentry.io/{_digits(rng, 7)}'
    add("SECRET", "sentry_dsn",
        f'Sentry.init(dsn="{sentry_dsn}")')

    firebase_key = "AAAA" + _alnum(rng, 7) + ":" + _b64url(rng, 130)
    add("SECRET", "firebase_server_key",
        f'FCM_SERVER_KEY={firebase_key}')

    supabase_jwt = "eyJ" + _b64url(rng, 24) + "." + _b64url(rng, 90) + "." + _b64url(rng, 40)
    add("SECRET", "supabase_service_role_key",
        f'SUPABASE_SERVICE_ROLE_KEY={supabase_jwt}')

    mapbox_key = "sk.ey" + _b64url(rng, 90)
    add("SECRET", "mapbox_secret_token",
        f'mapboxgl.accessToken = "{mapbox_key}";')

    dropbox_key = "sl." + _b64url(rng, 130)
    add("SECRET", "dropbox_refresh_token",
        f'DROPBOX_REFRESH_TOKEN="{dropbox_key}"')

    figma_key = "figd_" + _alnum(rng, 40, _B64URL)
    add("SECRET", "figma_personal_token",
        f'FIGMA_TOKEN={figma_key}')

    linear_key = "lin_api_" + _alnum(rng, 40)
    add("SECRET", "linear_api_key",
        f'LINEAR_API_KEY={linear_key}')

    airtable_key = "pat" + _alnum(rng, 14) + "." + _alnum(rng, 64)
    add("SECRET", "airtable_pat",
        f'AIRTABLE_TOKEN={airtable_key}')

    npm_tok = "npm_" + _alnum(rng, 36)
    add("SECRET", "npmrc_auth_token",
        f'//registry.npmjs.org/:_authToken={npm_tok}')

    pypi_tok = "pypi-AgEIcHlwaS5vcmc" + _b64url(rng, 90)
    add("SECRET", "pypirc_password",
        f'[pypi]\nusername = __token__\npassword = {pypi_tok}')

    dockerhub_tok = "dckr_pat_" + _b64url(rng, 27)
    add("SECRET", "dockerhub_pat",
        f'echo {dockerhub_tok} | docker login --username fabrikamci --password-stdin')

    hf_tok = "hf_" + _alnum(rng, 34)
    add("SECRET", "huggingface_token",
        f'HUGGINGFACE_TOKEN = "{hf_tok}"')

    notion_key = "secret_" + _alnum(rng, 43)
    add("SECRET", "notion_integration_token",
        f'NOTION_TOKEN={notion_key}')

    kakao_key = _hexs(rng, 32)
    add("SECRET", "kakao_rest_api_key",
        f'카카오 REST API 키: {kakao_key} — 지도 API 호출에 사용 중입니다.')

    naver_secret = _alnum(rng, 16)
    add("SECRET", "naver_client_secret",
        f'NAVER_CLIENT_SECRET={naver_secret}')

    data_gokr_key = _b64url(rng, 70) + "%3D%3D"
    add("SECRET", "data_go_kr_service_key",
        f'serviceKey={data_gokr_key}&numOfRows=10&pageNo=1')

    db_pw = _alnum(rng, 18)
    add("SECRET", "postgres_uri",
        f'DATABASE_URL=postgres://appuser:{db_pw}@db01.contoso.internal:5432/proddb')

    basic_pw = _alnum(rng, 14)
    add("SECRET", "basic_auth_url",
        f'curl https://svc_deploy:{basic_pw}@ci.fabrikam-corp.net/webhook/trigger')

    generic_pw = "Str0ng!Passw0rd_" + _alnum(rng, 4)
    add("SECRET", "generic_password_env",
        f'DB_PASSWORD={generic_pw}')

    curl_bearer = _b64url(rng, 40)
    add("SECRET", "curl_bearer_header",
        f'curl -H "Authorization: Bearer {curl_bearer}" https://api.contoso.net/v1/orders')

    jsonl_anthropic = "sk-ant-api03-" + _b64url(rng, 60) + "-" + _b64url(rng, 4)
    add("SECRET", "jsonl_transcript_tool_result",
        '{"type":"tool_result","tool_use_id":"toolu_01Ab2Cd3Ef4Gh5Ij6Kl7","content":'
        f'"export ANTHROPIC_API_KEY={jsonl_anthropic}\\nkey set successfully"}}')

    shell_hist_key = "AKIA" + _upper_alnum(rng, 16)
    add("SECRET", "shell_history_export",
        f'export AWS_ACCESS_KEY_ID={shell_hist_key}')

    jupyter_key = "sk-" + _alnum(rng, 48)
    add("SECRET", "jupyter_notebook_cell",
        '{"cell_type": "code", "source": ["import openai\\n", '
        f'"openai.api_key = \\"{jupyter_key}\\"\\n"], "outputs": []}}')

    compose_pw = _alnum(rng, 20)
    add("SECRET", "docker_compose_env",
        f'    environment:\n      - MYSQL_ROOT_PASSWORD={compose_pw}')

    k8s_secret_val = _b64url(rng, 32)
    add("SECRET", "k8s_secret_stringdata",
        f'stringData:\n  api-key: {k8s_secret_val}')

    gha_literal = "ghp_" + _alnum(rng, 36)
    add("SECRET", "github_actions_literal_leak",
        f'      - run: git push https://x-access-token:{gha_literal}@github.com/contoso/app.git')

    py_src_key = "sk-ant-api03-" + _b64url(rng, 50)
    add("SECRET", "python_source_hardcoded",
        f'client = anthropic.Anthropic(api_key="{py_src_key}")')

    js_src_key = "AIzaSy" + _alnum(rng, 33)
    add("SECRET", "js_source_hardcoded",
        f'const firebaseConfig = {{ apiKey: "{js_src_key}", authDomain: "fabrikam.firebaseapp.com" }};')

    r_src_key = "sk_live_" + _alnum(rng, 24)
    add("SECRET", "r_source_hardcoded",
        f'Sys.setenv(STRIPE_KEY = "{r_src_key}")')

    kr_prose_key = "ntn_" + _alnum(rng, 40)
    add("SECRET", "korean_prose_issued_key",
        f'발급받은 키는 {kr_prose_key} 입니다. 이 값을 팀 채널에 올리지 마세요.')

    kr_prose_auth = _hexs(rng, 24)
    add("SECRET", "korean_prose_auth_key",
        f'인증키: {kr_prose_auth} — 서버 배포 시 환경변수로 주입할 것.')

    # =====================================================================
    # KR_PII (~35+)
    # =====================================================================

    rrn1 = make_rrn(rng, foreign=False)
    add("KR_PII", "rrn_domestic",
        f'주민등록번호: {rrn1}')

    rrn2 = make_rrn(rng, foreign=False)
    add("KR_PII", "rrn_domestic_form",
        f'{make_name(rng)}, 주민번호 {rrn2}, 계약서 3조에 따라 서명함.')

    rrn3 = make_rrn(rng, foreign=True)
    add("KR_PII", "rrn_foreign_registration",
        f'외국인등록번호 {rrn3} 로 등록된 근로자입니다.')

    rrn4 = make_rrn(rng, foreign=False)
    add("KR_PII", "rrn_hr_record",
        f'인사기록카드: {make_name(rng)} / {rrn4} / 입사일 2019-03-04')

    m1, m2 = _digits(rng, 4), _digits(rng, 4)
    add("KR_PII", "phone_mobile",
        f'연락처: 010-{m1}-{m2}')

    m3, m4 = _digits(rng, 4), _digits(rng, 4)
    add("KR_PII", "phone_mobile_intl",
        f'긴급 연락처 +82-10-{m3}-{m4} 로 문자 주세요.')

    l1, l2 = _digits(rng, 3), _digits(rng, 4)
    add("KR_PII", "phone_landline_seoul",
        f'자택 전화 02-{l1}-{l2}')

    a1, a2 = _digits(rng, 4), _digits(rng, 4)
    add("KR_PII", "phone_landline_gyeonggi",
        f'031-{a1}-{a2}로 연락 부탁드립니다.')

    v1, v2 = _digits(rng, 4), _digits(rng, 4)
    add("KR_PII", "phone_voip",
        f'인터넷 전화: 070-{v1}-{v2}')

    email_local = _alnum(rng, 8, string.ascii_lowercase)
    add("KR_PII", "personal_email",
        f'담당자 이메일: {email_local}.kim87@fabrikammail.net')

    names_line = ", ".join(make_name(rng) for _ in range(4))
    add("KR_PII", "meeting_minutes_attendees",
        f'참석자: {names_line}')

    authors = f'{make_name(rng)}\u00b9, {make_name(rng)}\u00b2, {make_name(rng)}\u00b3'
    add("KR_PII", "paper_author_line",
        authors)

    add("KR_PII", "messenger_log",
        f'[오후 3:12] {make_name(rng)}: 네 알겠습니다, 자료 오늘 안에 보내드릴게요.')

    add("KR_PII", "form_label_name",
        f'성명: {make_name(rng)}    (인)')

    add("KR_PII", "honorific_title",
        f'{make_name(rng)} 대리님께서 먼저 검토해 주셨습니다.')

    acct_num = f'{_digits(rng,6)}-{_digits(rng,2)}-{_digits(rng,6)}'
    add("KR_PII", "bank_account",
        f'국민은행 {acct_num} 예금주 {make_name(rng)}')

    card1 = make_card(rng, "4556")
    add("KR_PII", "credit_card_luhn",
        f'카드번호 {card1} 유효기간 08/29')

    passport = "M" + _digits(rng, 8)
    add("KR_PII", "passport_number",
        f'여권번호: {passport}')

    dl = f'{rng.randint(11,29):02d}-{rng.randint(0,99):02d}-{_digits(rng,6)}-{_digits(rng,2)}'
    add("KR_PII", "drivers_license",
        f'운전면허번호 {dl}')

    brn1 = make_brn(rng)
    add("KR_PII", "business_registration_number",
        f'사업자등록번호: {brn1}')

    add("KR_PII", "address_road_name",
        f'서울특별시 강남구 테헤란로 {rng.randint(10,500)}, {rng.randint(2,20)}층 {rng.randint(201,999)}호')

    add("KR_PII", "address_lot_number",
        f'경기도 성남시 분당구 정자동 {rng.randint(1,999)}-{rng.randint(1,30)}번지')

    add("KR_PII", "address_with_postcode",
        f'(우) {_digits(rng,5)}  대전광역시 유성구 대학로 {rng.randint(1,300)}')

    add("KR_PII", "birth_date_prose",
        f'{make_name(rng)}님은 {rng.randint(1970,2005)}년 {rng.randint(1,12)}월 {rng.randint(1,28)}일생입니다.')

    add("KR_PII", "student_id_with_name",
        f'학번 {rng.randint(2015,2025)}{_digits(rng,5)} {make_name(rng)}')

    add("KR_PII", "employee_id_with_name",
        f'사번 EMP-{_digits(rng,5)} {make_name(rng)}')

    plate1 = f'{rng.randint(10,99)}\uac00{_digits(rng,4)}'
    add("KR_PII", "vehicle_plate_old",
        f'차량번호 {plate1} 차주 확인 요청')

    plate2 = f'{rng.randint(100,999)}\ud5c8{_digits(rng,4)}'
    add("KR_PII", "vehicle_plate_new",
        f'주차 위반 차량 {plate2} 견인 예정')

    rrn5 = make_rrn(rng, foreign=False)
    add("KR_PII", "rrn_insurance_claim",
        f'보험금 청구인 {make_name(rng)}({rrn5}) 계좌로 지급 예정입니다.')

    add("KR_PII", "phone_and_email_signature",
        f'{make_name(rng)} 드림 / 010-{_digits(rng,4)}-{_digits(rng,4)} / '
        f'{_alnum(rng,6,string.ascii_lowercase)}92@fabrikammail.net')

    card2 = make_card(rng, "5412")
    add("KR_PII", "credit_card_spaced",
        f'{card2.replace("-", " ")} 로 결제 진행 부탁드립니다.')

    names_line2 = ", ".join(make_name(rng) for _ in range(3))
    add("KR_PII", "messenger_group_intro",
        f'새로 합류하신 {names_line2} 님들 환영합니다!')

    add("KR_PII", "address_apartment",
        f'인천광역시 연수구 송도과학로 {rng.randint(1,100)} {rng.randint(101,120)}동 {rng.randint(1001,2005)}호')

    rrn6 = make_rrn(rng, foreign=True)
    add("KR_PII", "rrn_foreign_lease",
        f'임차인 외국인등록번호: {rrn6}')

    brn2 = make_brn(rng)
    add("KR_PII", "business_registration_invoice",
        f'공급자 등록번호 {brn2}, 상호 (주)파브리캄')

    add("KR_PII", "birth_date_short_form",
        f'생년월일 {rng.randint(70,99):02d}.{rng.randint(1,12):02d}.{rng.randint(1,28):02d}')

    # =====================================================================
    # INFRA (~20+)
    # =====================================================================

    add("INFRA", "windows_user_path",
        r'C:\Users\minsu.kim\Documents\quarterly_report.docx')

    add("INFRA", "windows_path_json_escaped",
        r'"logPath": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\build.log"')

    add("INFRA", "git_bash_path",
        '/c/Users/dpark/projects/internal-app/config.yml')

    add("INFRA", "wsl_path",
        '/mnt/c/Users/yoonji/scratch/dataset_v2')

    add("INFRA", "linux_service_home",
        '/home/svc-deploy/app/current/settings.py')

    add("INFRA", "macos_user_path",
        '/Users/taeyang.lee/Library/Application Support/ContosoApp/config.json')

    add("INFRA", "tilde_expanded_log",
        'ERROR: cannot write to ~jhkim/logs/error.log (permission denied)')

    add("INFRA", "onedrive_org_name",
        r'C:\Users\dpark\OneDrive - Contoso Ltd\Shared Documents\Finance\budget.xlsx')

    add("INFRA", "sharepoint_url",
        'https://fabrikam.sharepoint.com/sites/RnD/Shared%20Documents/Forms/AllItems.aspx')

    add("INFRA", "gdrive_shared_drive",
        '공유 드라이브 "Fabrikam Team Drive"에 자료를 업로드했습니다.')

    add("INFRA", "private_ip_10",
        'backend service listening on 10.42.3.17:8080')

    add("INFRA", "private_ip_172",
        'internal DB host at 172.20.5.11, port 5432')

    add("INFRA", "private_ip_192",
        'printer share \\\\192.168.1.55\\office-printer')

    add("INFRA", "tailscale_cgnat",
        'ssh dhan@100.101.102.5  # devbox via tailscale')

    add("INFRA", "internal_hostname_local",
        'curl http://build.contoso.local/api/status')

    add("INFRA", "internal_hostname_corp",
        'nslookup db01.fabrikam.corp')

    add("INFRA", "internal_hostname_internal",
        'connecting to api.internal for the nightly sync job')

    add("INFRA", "ssh_config_block",
        'Host devbox\n    HostName 100.101.102.5\n    User dhan\n    Port 22\n    IdentityFile ~/.ssh/id_ed25519_devbox')

    add("INFRA", "vpn_endpoint",
        'VPN gateway: vpn.contoso-corp.net:1194 (OpenVPN, UDP)')

    add("INFRA", "vpn_uri_scheme",
        'openvpn://10.8.0.1/client-config?profile=fabrikam-remote')

    add("INFRA", "windows_user_path_scratch",
        r'D:\Users\hyunwoo.park\scratch\model_fit_v3\out.csv')

    add("INFRA", "linux_deploy_key_path",
        '/home/ci-runner/.ssh/deploy_key_fabrikam')

    # =====================================================================
    # NEG (~70+) — hard negatives
    # =====================================================================

    add("NEG", "placeholder_sk_x",
        'ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')

    add("NEG", "placeholder_your_key",
        'export API_KEY=YOUR_API_KEY_HERE')

    add("NEG", "placeholder_angle_brackets",
        'aws_access_key_id = <AWS_ACCESS_KEY_ID>')

    add("NEG", "placeholder_changeme",
        'DB_PASSWORD=changeme')

    add("NEG", "aws_doc_example_key",
        'aws_access_key_id = AKIAIOSFODNN7EXAMPLE')

    add("NEG", "aws_doc_example_secret",
        'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

    add("NEG", "stripe_doc_example_key",
        'stripe.api_key = "' + 'sk_' + 'test_' + '4eC39HqLyjWDarjtT1zdp7dc' + '"')

    add("NEG", "google_doc_example_key",
        'const apiKey = "AIzaSyDOCS_EXAMPLE_KEY_1234567890abc";')

    add("NEG", "placeholder_xxxx_dashes",
        'token: xxxx-xxxx-xxxx-xxxx')

    add("NEG", "git_commit_sha",
        'commit a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4')

    add("NEG", "uuid4",
        'request_id: 3fa85f64-5717-4562-b3fc-2c963f66afa6')

    add("NEG", "ulid",
        'trace_id: 01ARZ3NDEKTSV4RRFFQ69G5FAV')

    add("NEG", "base64_config_blob",
        'settings_b64: eyJ0aGVtZSI6ICJkYXJrIiwgImxhbmciOiAia28ifQ==  # UI prefs only')

    add("NEG", "transcript_msg_id",
        '{"id": "msg_01AbCdEfGhIjKlMnOpQrStUv", "role": "assistant"}')

    add("NEG", "transcript_tool_id",
        '"tool_use_id": "toolu_01XyZaBcDeFgHiJkLmNoPqRs"')

    add("NEG", "transcript_req_id",
        'X-Request-Id: req_9f8e7d6c5b4a3210')

    add("NEG", "transcript_call_id",
        '"call_id": "call_3f2e1d0c9b8a"')

    add("NEG", "semver_package",
        'requires: contoso-sdk@2.14.3')

    add("NEG", "semver_prerelease",
        'installed fabrikam-cli v1.0.0-beta.2')

    add("NEG", "doi",
        'doi:10.1038/s41586-023-12345-6')

    add("NEG", "pmid",
        'PMID: 34567890')

    add("NEG", "orcid",
        'ORCID: 0000-0002-1825-0097')

    add("NEG", "isbn",
        'ISBN 978-3-16-148410-0')

    add("NEG", "cas_number",
        'D-glucose (CAS 50-99-7) was dissolved in buffer.')

    add("NEG", "timestamp_iso",
        'event_time: 2026-09-24T14:32:01Z')

    add("NEG", "timestamp_epoch",
        'created_at=1695555555')

    add("NEG", "public_ip_google_dns",
        'nameserver 8.8.8.8')

    add("NEG", "rfc5737_doc_ip_a",
        'example host at 203.0.113.42 in the documentation range')

    add("NEG", "rfc5737_doc_ip_b",
        'test target 198.51.100.7 (TEST-NET-2)')

    add("NEG", "rfc5737_doc_ip_c",
        'sample config points to 192.0.2.1')

    add("NEG", "localhost_url",
        'API base: http://localhost:8000/api/v1')

    add("NEG", "localhost_loopback",
        'psql -h 127.0.0.1 -p 5432 -U dev')

    add("NEG", "km_value",
        'Km = 0.42 mM for the wild-type enzyme under these conditions.')

    add("NEG", "kcat_value",
        'kcat = 12.3 s-1, consistent with previous reports.')

    add("NEG", "od600_value",
        'Cells were harvested at OD600 = 0.85.')

    add("NEG", "nadh_concentration",
        '0.2 mM NADH was added to initiate the coupled assay.')

    add("NEG", "rate_constant_scientific",
        'k_cat/K_M = 1.2e5 M-1 s-1 for the mutant variant.')

    add("NEG", "ph_buffer",
        'Reactions were run in 50 mM phosphate buffer, pH 7.4.')

    add("NEG", "primer_sequence",
        "Forward primer: 5'-ATGCGTACGTTAGCCGGATCAA-3'")

    add("NEG", "plasmid_name",
        'The gene was cloned into pET-28a(+) using NdeI/XhoI sites.')

    add("NEG", "ecoli_strain",
        'Protein was expressed in E. coli BL21(DE3) at 18 degC overnight.')

    add("NEG", "korean_prose_experiment_date",
        '실험은 2026년 3월 15일에 진행되었으며 반응은 37도에서 24시간 수행되었다.')

    add("NEG", "korean_prose_yield",
        '이번 배치의 수율은 82.4%로 이전 실험 대비 소폭 상승하였다.')

    add("NEG", "korean_role_advisor",
        '지도교수님께 실험 결과를 오늘 오후에 보고드렸습니다.')

    add("NEG", "korean_role_contact_person",
        '문의사항이 있으시면 담당자에게 연락 바랍니다.')

    add("NEG", "korean_role_faculty_meeting",
        '다음 주 화요일 오전 10시에 교수회의 일정이 공지되었습니다.')

    add("NEG", "korean_role_phd_student",
        '박사과정생 모집 공고가 연구실 홈페이지에 게시되었습니다.')

    add("NEG", "korean_role_teachers_plural",
        '선생님들 오늘도 고생 많으셨습니다, 감사합니다.')

    add("NEG", "company_hotline_1588",
        '고객센터 1588-1234 (평일 09:00-18:00 운영)')

    add("NEG", "company_hotline_1588_b",
        '기술지원 문의는 1588-5678로 연락 주세요.')

    add("NEG", "generic_path_usr_bin",
        'shebang line points to /usr/bin/python3')

    add("NEG", "generic_path_program_files",
        r'installed under C:\Program Files\Git\bin\bash.exe')

    add("NEG", "generic_path_dotconfig",
        'config template lives at ~/.config/gh/config.yml')

    add("NEG", "generic_path_relative_data",
        'raw files are read from ./data/raw/sample.csv')

    add("NEG", "example_com_email_contact",
        'For support, email contact@example.com.')

    add("NEG", "example_com_email_test",
        'test.user@example.org was used as the placeholder account.')

    add("NEG", "git_github_ssh_remote",
        'git remote add origin git@github.com:octocat/Hello-World.git')

    add("NEG", "password_policy_korean",
        '비밀번호는 8자 이상이어야 하며 특수문자를 포함해야 합니다.')

    add("NEG", "password_policy_english",
        'Passwords must be at least 12 characters and include a symbol.')

    add("NEG", "config_constant_retries",
        'MAX_RETRIES = 5')

    add("NEG", "config_constant_timeout",
        'TIMEOUT_SECONDS = 30')

    add("NEG", "config_constant_batch",
        'BATCH_SIZE: 64')

    add("NEG", "token_count_korean",
        '이번 요청은 1,204 토큰을 사용했습니다.')

    add("NEG", "token_count_english",
        'This response used 842 output tokens.')

    add("NEG", "generic_word_rotate_key",
        'Rotate your API key every 90 days as a security best practice.')

    add("NEG", "generic_word_never_share_password",
        'Never share your password with anyone, including support staff.')

    add("NEG", "generic_word_session_token_expiry",
        'The session token expires after 1 hour of inactivity.')

    add("NEG", "generic_word_secret_management_doc",
        'This chapter covers secret management strategies for microservices.')

    add("NEG", "version_pin_requirements",
        'requests==2.31.0')

    add("NEG", "public_ip_cloudflare_dns",
        'secondary resolver set to 1.1.1.1')

    add("NEG", "hash_sha256_example",
        'sha256sum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    add("NEG", "generic_word_key_variable_name",
        'for key, value in config.items():\n    print(key, value)')

    add("NEG", "generic_word_token_variable_name",
        'token = tokenizer.encode(sentence)')

    add("NEG", "korean_prose_no_person_summary",
        '이번 분기 실험 결과 요약본은 회의 자료 폴더에 업로드되었습니다.')

    add("NEG", "molarity_units_general",
        'The stock solution was prepared at 1.5 M and stored at 4 degC.')

    return rows


def _main() -> None:
    rows = corpus()
    counts: dict[str, int] = {}
    for cat, _sub, _line in rows:
        counts[cat] = counts.get(cat, 0) + 1
    total = len(rows)
    for cat in sorted(counts):
        print(f"{cat}: {counts[cat]}")
    print(f"TOTAL: {total}")


if __name__ == "__main__":
    _main()

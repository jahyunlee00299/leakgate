"""Korean personal information plus the universal identifiers (email, card).

Numbers that are ambiguous on their own (passport, bank account, driver
licence) are reported only when a context word sits just before them; numbers
with a checksum (card, business registration) are reported on the checksum.
Resident registration numbers issued after October 2020 carry no checksum, so a
valid birth date plus a valid gender/century digit is accepted as well.
"""
from __future__ import annotations

import re
from datetime import date

from leakgate.detectors.base import Rule, scan_rules
from leakgate.finding import Finding

# The ~100 most common Korean surnames cover >99% of the population.
SURNAMES = frozenset(
    "김이박최정강조윤장임한오서신권황안송류전홍고문양손배백허유남심노하곽성차주우구민진나지엄채원천방공현함변염여추도소석선설마길연위표명기반라왕금옥육인맹제모탁국어은편용예경봉사부가복태목형피두감음빈동온호범좌팽승간상갈단견당화창"
)
# Words ending in a title that name a ROLE, not a person.
ROLE_WORDS = frozenset({
    "지도교수", "담당교수", "책임교수", "주임교수", "겸임교수", "객원교수", "부교수", "정교수", "조교수",
    "석좌교수", "명예교수", "초빙교수", "연구교수", "전임교수", "지도박사", "담당박사", "박사후연구원",
    "담당선생", "학과선생", "담임선생", "책임연구원", "선임연구원", "수석연구원", "전임연구원", "위촉연구원",
    "대학원생", "학부생", "연구원", "학생", "교수", "박사", "선생",
})
NOT_NAMES = frozenset({
    "완료", "확인", "예정", "없음", "미정", "필요", "진행", "요청", "검토", "담당", "작성", "승인", "대기",
    "본인", "전체", "공통", "각자", "팀장", "부서", "관리", "센터", "없다", "해당", "기타", "미상",
    # Modifiers that precede a title without naming anyone (`신입 연구원`, `선임 연구원`).
    "신입", "신규", "인턴", "막내", "선배", "후배", "동료", "전임", "수석", "책임", "선임", "주니어",
    "시니어", "초보", "여러", "모든", "각각", "다른", "우리", "저희", "같은", "새로운", "외부", "내부",
    "객원", "명예", "전공", "지도", "담임", "원로", "현직", "전직", "예비", "정규",
})
TITLE = r"(?:교수|박사|선생|연구원|원장|소장|팀장|실장|부장|과장|차장|대리|주임|사원|학생|씨)"
PARTICLE = r"(?:님|께서|께|에게서|에게|한테|이|가|은|는|을|를|과|와|의|도|만)*"


def _rrn(m: re.Match) -> str | None:
    digits = re.sub(r"\D", "", m.group("v"))
    yy, mm, dd, g = int(digits[:2]), int(digits[2:4]), int(digits[4:6]), int(digits[6])
    century = {1: 1900, 2: 1900, 5: 1900, 6: 1900, 3: 2000, 4: 2000, 7: 2000, 8: 2000, 9: 1800, 0: 1800}[g]
    try:
        date(century + yy, mm, dd)
    except ValueError:
        return None
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    check_ok = (11 - sum(int(a) * b for a, b in zip(digits, w)) % 11) % 10 == int(digits[12])
    ctx = re.search(r"주민|외국인등록|resident|RRN", m.string[max(0, m.start() - 20):m.start()], re.I)
    if not re.search(r"\D", m.group("v")):
        # 13 bare digits are as often a patent/DOI/order number (seen in real PDFs);
        # without a separator, demand the checksum or a label.
        return m.group("v") if (check_ok or ctx) else None
    return m.group("v") if (check_ok or ctx or g in (1, 2, 3, 4)) else None


def _luhn(m: re.Match) -> str | None:
    digits = [int(c) for c in re.sub(r"\D", "", m.group(0))]
    if len(set(digits)) <= 2:                  # 0000-0000-… / 1111-… are fillers
        return None
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return m.group(0) if total % 10 == 0 else None


def _brn(m: re.Match) -> str | None:
    d = [int(c) for c in re.sub(r"\D", "", m.group("v"))]
    w = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(a * b for a, b in zip(d, w)) + (d[8] * 5) // 10
    ok = (10 - s % 10) % 10 == d[9]
    ctx = re.search(r"사업자|business", m.string[max(0, m.start() - 20):m.start()], re.I)
    return m.group("v") if ok or ctx else None


def _email(m: re.Match) -> str | None:
    local, _, domain = m.group(0).rpartition("@")
    dom = domain.lower()
    if local.lower() in {"git", "noreply", "no-reply"} or m.string[m.end():m.end() + 1] == ":"             or re.fullmatch(r"[\d.]+", domain):      # user@<ipv4> is an ssh target, not an email
        return None
    if dom.split(".")[0] in {"example", "test", "localhost", "domain", "email", "company"} \
            or dom.endswith((".example", ".test", ".invalid", ".local", "noreply.github.com")) \
            or re.fullmatch(r"[\w.]*\.(?:png|jpe?g|gif|svg|webp)", dom):
        return None
    return m.group(0)


def _person(m: re.Match) -> str | None:
    name = m.group("v")
    whole = re.sub(PARTICLE + "$", "", m.group(0).replace(" ", ""))
    if name[0] not in SURNAMES or whole in ROLE_WORDS or name in NOT_NAMES:
        return None
    if any(whole.startswith(r) for r in ROLE_WORDS if len(r) > 2):
        return None
    return name


def _birthdate(m: re.Match) -> str | None:
    return m.group("v") or m.group("w")


def _name_list(m: re.Match) -> str | None:
    """`참석자: 한서연, 오태양` — report the leading run of items that look like names.  # leakgate:allow

    Stops at the first item that is not a name, so `담당: 박서연, 검토: 이도윤`  # leakgate:allow
    yields `박서연` here (and `이도윤` from its own label) instead of nothing.  # leakgate:allow
    """
    text = m.group("v")
    end = 0
    for part in re.finditer(r"[가-힣]+", text):
        n = part.group(0)
        if not (2 <= len(n) <= 4 and n[0] in SURNAMES and n not in NOT_NAMES and n not in ROLE_WORDS):
            break
        end = part.end()
    return text[:end] if end else None

# A number glued to '.', '+', '-' or a hex letter is part of a float, a UUID or a
# coordinate, not an identifier: measured on 90k site-packages files, bare
# (?<!\d) boundaries turned float digits into 11k "cards" and 900 "RRNs".
NL = r"(?<![\w.+\-])"
NR = r"(?![\w.\-]\w|\d)"


def _ctx(words: str, span: int = 15) -> str:
    return r"(?:" + words + r")[^\n\d]{0," + str(span) + r"}"


RULES: list[Rule] = [
    ("kr-rrn", re.compile(NL + r"(?P<v>\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[-\s]?[0-9]\d{6})" + NR), _rrn),
    ("kr-mobile", re.compile(NL + r"(?:\+82[-\s]?1[016789]|01[016789])[-.\s]?\d{3,4}[-.\s]?\d{4}" + NR), None),
    ("kr-landline", re.compile(NL + r"(?:\+82[-\s]?|0)(?:2|[3-6][1-5])[-.)\s]\d{3,4}[-.\s]\d{4}" + NR), None),
    ("email", re.compile(r"(?<![\w.+-])[A-Za-z0-9][\w.+-]*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"), _email),
    # Issuer prefix required (Visa 4, Mastercard 2/5, Amex 34/37, Discover/UnionPay 6,
    # JCB 35, Korean domestic 9) and ONE consistent separator throughout.
    ("payment-card", re.compile(NL + r"(?<!\d[\s-])(?:[2-69]\d{3}(?P<s>[-\s]?)\d{4}(?P=s)\d{4}(?P=s)\d{4}"
                                     r"|3[47]\d{2}(?P<t>[-\s]?)\d{6}(?P=t)\d{5})(?![\s-]\d)" + NR), _luhn),
    ("kr-business-reg-no", re.compile(NL + r"(?P<v>\d{3}-\d{2}-\d{5})" + NR), _brn),
    ("bank-account", re.compile(
        _ctx(r"계좌|은행|농협|국민|신한|우리|하나|기업|카카오뱅크|케이뱅크|토스|새마을|우체국|수협|신협|account")
        + r"(?P<v>\d{2,6}-\d{2,6}-\d{2,7}(?:-\d{1,3})?)(?!\d)", re.I), None),
    ("passport-no", re.compile(_ctx(r"여권|passport", 12) + r"(?P<v>[MSRGDT]\d{8}|[MSRGDT]\d{3}[A-Z]\d{4})\b", re.I), None),
    ("kr-driver-license", re.compile(_ctx(r"면허|license", 12) + r"(?P<v>\d{2}-\d{2}-\d{6}-\d{2})(?!\d)", re.I), None),
    ("kr-address", re.compile(
        r"(?P<v>(?:서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충청북|충청남|충북|충남|전라북|전라남|전북|전남|경상북|경상남|경북|경남|제주)"
        r"[가-힣]*\s+(?:[가-힣]+(?:시|군|구)\s+){1,2}"
        r"(?:(?:[가-힣0-9]+(?:읍|면|동|가)\s+)?[가-힣0-9]+(?:로|길)\s*\d+(?:-\d+)?"      # road-name
        r"|(?:[가-힣0-9]+(?:읍|면)\s+)?[가-힣0-9]+(?:동|리|가)\s*\d+(?:-\d+)?\s*(?:번지)?))"), None),  # lot-number
    ("kr-name-title", re.compile(r"(?<![가-힣])(?P<v>[가-힣]{2,4}?)\s?" + TITLE + PARTICLE + r"(?![가-힣])"), _person),
    ("kr-name-labeled", re.compile(
        r"(?:담당자?|검토자?|작성자?|저자|책임자|연락처|이름|성명|성함|보호자|신청인|대표자?|승인자?|결재자?|수신인?|발신인?"
        r"|참석자?|참여자|명단|구성원|위원)(?:\s*(?:목록|명단|명))?"
        r"\s*[:：]\s*(?P<v>[가-힣]{2,4}(?:\s*(?:[,、·/]|및)\s*[가-힣]{2,4})*)(?![가-힣])"), _name_list),
    ("kr-birthdate", re.compile(
        r"(?P<v>(?:[가-힣]{2,4}\s*\(?\s*)?(?:19|20)\d{2}\s*[.\-/년]\s*\d{1,2}\s*[.\-/월]\s*\d{1,2}\s*일?\.?\s*"
        r"(?:생|출생|년생))|(?:생년월일|생일|DOB|date of birth)\s*[:：]?\s*"
        r"(?P<w>(?:19|20)\d{2}\s*[.\-/년]\s*\d{1,2}\s*[.\-/월]\s*\d{1,2}일?)", re.I), _birthdate),
]


class KoreanPiiDetector:
    name = "kr-pii"

    def scan(self, text: str) -> list[Finding]:
        return scan_rules(text, RULES, "pii")


def _register_gates() -> None:
    from leakgate.detectors.base import gate
    digits, hangul = r"\d{4}", "[가-힣]"
    for name in ("kr-rrn", "kr-mobile", "kr-landline", "payment-card", "kr-business-reg-no"):
        gate(name, digits)
    gate("email", "@")
    for name in ("bank-account", "passport-no", "kr-driver-license", "kr-birthdate"):
        gate(name, r"\d")
    for name in ("kr-address", "kr-name-title", "kr-name-labeled"):
        gate(name, hangul)


_register_gates()

"""Credential detector: vendor-prefixed tokens + keyword assignments.

Vendor prefixes are specific enough to report on sight. Keyword assignments
(`password = ...`, `비밀번호: ...`) are only reported when the value survives the
placeholder test and looks opaque — that pairing is what keeps documentation
(`api_key = os.environ[...]`, `<YOUR_API_KEY>`) from being flagged.
"""
from __future__ import annotations

import re

from leakgate.detectors.base import Rule, default_value, scan_rules
from leakgate.finding import Finding
from leakgate.placeholder import is_placeholder, shannon_entropy


def _not_placeholder(m: re.Match) -> str | None:
    v = default_value(m)
    return None if is_placeholder(v, m.group(0)) else v


def _opaque_generic(m: re.Match) -> str | None:
    """Unprefixed `sk-…` also names CSS classes and algorithms (`sk-toggleable__label`,
    `sk-ecdsa-sha2-nistp256`): demand digits and real entropy in the body."""
    v = _not_placeholder(m)
    if not v:
        return None
    body = v.split("-", 1)[1]
    if "__" in body or sum(c.isdigit() for c in body) < 2 or shannon_entropy(body) < 3.5:
        return None
    if all(w.isalpha() or w.isdigit() for w in re.split(r"[-_]", body)) and "-" in body:
        return None                      # dash-joined words / version parts
    return v


# `user_api_key_dict.api_key`, `Name.Function`, `Optional[Auth]`: code, not a value.
_CODE_EXPR = re.compile(
    r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$"        # dotted attribute access
    r"|[\[\](){}]"                                # call / subscript / literal
    r"|^_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+$"         # snake_case variable name
    r"|^(?:[A-Z][a-z]+){2,}$"                     # CamelCase word run
    r"|^[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?$")    # a plain number


def _opaque_assignment(m: re.Match) -> str | None:
    v = m.group("v").strip("\"'`")
    if len(v) < 8 or _CODE_EXPR.search(v) or is_placeholder(v, m.group(0)):
        return None
    if v.lower() in {"true", "false", "required", "optional"}:
        return None
    has_mix = any(c.isdigit() for c in v) and any(c.isalpha() for c in v)
    if not has_mix and shannon_entropy(v) < 3.0:
        return None
    return v


_B = r"(?<![A-Za-z0-9_\-])"    # left boundary that tolerates quotes/'=' but not token chars
_E = r"(?![A-Za-z0-9_\-])"

RULES: list[Rule] = [
    ("anthropic-key", re.compile(_B + r"sk-ant-(?:api\d{2}-|admin\d{2}-)?[A-Za-z0-9_\-]{32,}"), _not_placeholder),
    ("openrouter-key", re.compile(_B + r"sk-or-v\d-[A-Za-z0-9]{32,}"), _not_placeholder),
    ("openai-project-key", re.compile(_B + r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"), _not_placeholder),
    ("openai-style-key", re.compile(_B + r"sk-[A-Za-z0-9_\-]{20,}"), _opaque_generic),
    ("github-token", re.compile(_B + r"gh[pousr]_[A-Za-z0-9]{36,}"), _not_placeholder),
    ("github-fine-grained", re.compile(_B + r"github_pat_[A-Za-z0-9_]{50,}"), _not_placeholder),
    ("gitlab-token", re.compile(_B + r"glpat-[A-Za-z0-9_\-]{20,}"), _not_placeholder),
    ("slack-token", re.compile(_B + r"xox[baprs]-[A-Za-z0-9\-]{10,}"), _not_placeholder),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"), None),
    ("aws-access-key-id", re.compile(_B + r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}" + _E), _not_placeholder),
    ("aws-secret-key", re.compile(
        r"(?i)aws_?secret(?:_access)?_?key[\"']?\s*[:=]\s*[\"']?(?P<v>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
     _not_placeholder),
    ("google-api-key", re.compile(_B + r"AIza[A-Za-z0-9_\-]{35}" + _E), _not_placeholder),
    ("stripe-key", re.compile(_B + r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"), _not_placeholder),
    ("notion-token", re.compile(_B + r"(?:ntn_[A-Za-z0-9]{40,}|secret_[A-Za-z0-9]{43})" + _E), _not_placeholder),
    ("huggingface-token", re.compile(_B + r"hf_[A-Za-z0-9]{30,}" + _E), _not_placeholder),
    ("sendgrid-key", re.compile(_B + r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), None),
    ("telegram-bot-token", re.compile(r"(?<![0-9])\d{8,10}:AA[A-Za-z0-9_\-]{33}" + _E), None),
    ("jwt", re.compile(_B + r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), None),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"), None),
    ("url-embedded-password", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver"
        r"|https?|ftps?|sftp|smtps?|imaps?|git\+https?)"
        r"://[^:\s/@]+:(?P<v>[^@\s/]{4,})@"), _not_placeholder),
    ("azure-account-key", re.compile(
        r"(?i)(?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*(?P<v>[A-Za-z0-9+/%]{30,}={0,2})"),
     _not_placeholder),
    ("discord-bot-token", re.compile(
        _B + r"[A-Za-z0-9_\-]{24,28}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}" + _E), _not_placeholder),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/\-]{24,}=*)"), _not_placeholder),
    ("credential-assignment", re.compile(
        # A lookbehind, not a repeated `(?:\w+_)*` prefix: the repeated group
        # backtracks quadratically on long identifier-like lines (measured 1.2 s
        # on one 6 000-char line). SLACK_TOKEN / hf_token still match via `_`.
        r"(?i)(?:(?<=[_\-])|(?<![A-Za-z0-9]))"
        r"(?:api[_\-]?key|apikey|secret(?:[_\-]?(?:access)?[_\-]?key)?|access[_\-]?token|auth[_\-]?token"
        r"|refresh[_\-]?token|client[_\-]?secret|app[_\-]?password|password|passwd|pwd|token|private[_\-]?key"
        r"|비밀번호|패스워드|암호|인증키|토큰"
        # Bare KEY/PAT only as a suffix (SERVICE_ROLE_KEY, GH_PAT): alone,
        # `key = ...` is too common in ordinary code to mean a credential.
        r"|(?<=[_\-])(?-i:KEY|PAT))"      # env-var style only; `result_key` is a dict key
        r"(?![A-Za-z0-9])[\"']?\s*[:=]\s*[\"'`]?(?P<v>[^\s\"'`,;]{8,})"), _opaque_assignment),
]


class SecretDetector:
    name = "secrets"

    def scan(self, text: str) -> list[Finding]:
        return scan_rules(text, RULES, "secret")


def _register_gates() -> None:
    from leakgate.detectors.base import gate
    for name, anchor in {
        "anthropic-key": "sk-ant-", "openrouter-key": "sk-or-", "openai-project-key": "sk-",
        "openai-style-key": "sk-", "github-token": r"gh[pousr]_", "github-fine-grained": "github_pat_",
        "gitlab-token": "glpat-", "slack-token": "xox", "slack-webhook": "hooks.slack",
        "aws-access-key-id": r"A[KSBC][IC]A", "google-api-key": "AIza", "stripe-key": "_live_",
        "notion-token": "ntn_|secret_", "huggingface-token": "hf_", "sendgrid-key": r"SG\.",
        "telegram-bot-token": r"\d:AA", "jwt": "eyJ", "private-key-block": "PRIVATE KEY",
        "url-embedded-password": "://", "bearer-token": "(?i)bearer", "discord-bot-token": r"\.[\w-]{6}\.",
        "aws-secret-key": "(?i)aws", "azure-account-key": "(?i)accountkey|sharedaccess",
        "credential-assignment": r"(?i)key|pat|token|secret|pass|pwd|비밀번호|패스워드|암호|인증키|토큰",
    }.items():
        gate(name, anchor)


_register_gates()

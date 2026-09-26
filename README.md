# leakgate

A pre-publish gate for what generic secret scanners miss: **Korean personal
data, local usernames and internal hosts, and your organisation's unpublished
terms** — alongside ordinary API keys. Built for researchers who publish code,
notebooks and AI-agent transcripts (Claude Code / Codex JSONL).

```bash
pip install leakgate                 # stdlib only, Python 3.11+
leakgate scan .                      # report (exit 1 if anything found)
leakgate redact logs/ --apply        # mask in place, JSONL-safe
```

## Why another scanner

Excellent scanners already exist, and leakgate does not try to replace them:
[gitleaks](https://github.com/gitleaks/gitleaks) for vendor secrets,
[maskingtape](https://github.com/ChoHyeonChan/maskingtape) and
[ko-pii](https://github.com/Marker-Inc-Korea/ko-pii) for Korean PII,
[neuralyzer](https://github.com/sandeepsirodia/neuralyzer) for agent
transcripts. Each covers one axis. A repository you are about to make public
leaks on all of them at once — a traceback with `C:\Users\<you>`, a meeting
note with a colleague's phone number, an unpublished compound name, an API key
a helper script echoed into a log. leakgate checks all four axes in one pass
and can call the specialised tools as extra engines.

| Axis | What it catches |
| --- | --- |
| `secret` | ~30 vendor formats (incl. Docker Hub, Airtable; Kakao and 공공데이터포털 keys by context), `KEY=`/`password:`/`비밀번호:` assignments, URLs with passwords, JWTs, private-key blocks — with placeholder discrimination (`<YOUR_KEY>`, `sk-xxxx`, `os.environ[...]` pass) |
| `pii` | 주민/외국인등록번호 (checksum or post-2020 form), mobile/landline, email, card (Luhn + issuer), 사업자번호 (checksum), bank account/passport/licence (with context), road-name and lot-number addresses, names with titles, labels and lists, birth dates, vehicle plates, student/employee IDs, and anyone on your `names` list |
| `infra` | usernames in Windows / JSON-escaped / git-bash / POSIX / macOS home paths, OneDrive and SharePoint tenants, RFC 1918 and Tailscale/CGNAT addresses, internal hostnames |
| `custom` | your own dictionary: codenames, private repo names, regexes, and **metric words whose nearby number is sensitive** (`yield`, `titer`, `MPSP`) |
| known values | point it at your real secrets file (`--known-secrets secrets.json` / `.env`): every value is matched literally, so your own key is caught whatever its format. Values are never printed. |

## Benchmark

`bench/run.py` scores every tool line by line on four synthetic corpora
(credentials generated at runtime, fictional people and organisations):

- `dev` — the corpus the rules were written against (optimistic by construction),
- `heldout` — a blind set written by an agent that never saw the rules; its
  misses were then used to fix general gaps, so it is no longer blind,
- `heldout2` — a second blind set, first run after the 0.1.0 rules were frozen;
  its known gaps drove the 0.2.0 rules, so it is no longer blind either,
- `heldout3` — a third blind set (270 lines), written for 0.2.0 by an agent that
  read none of the sources, tests, README or other sets, first run **after** the
  0.2.0 rules were frozen. **This is the honest number for 0.2.0.**

`heldout3` (60 secrets, 70 Korean PII, 30 infra, 110 hard negatives):

| leakgate | Secrets | Korean PII | Infra | False positives |
| --- | --- | --- | --- | --- |
| 0.1.0 | 49 | 44 | 23 | 0 |
| **0.2.0, rules frozen (the honest number)** | **49** | **46** | **23** | **0** |
| 0.2.0 after fixing four general gaps it exposed | 55 | 48 | 23 | 0 |

The four fixes (PyPI tokens, Discord webhooks, session cookies, hyphenated
employee IDs) came from reading heldout3's misses, so the last row is not blind.
What it still misses is mostly **names of people nobody listed**: 17 of the 22
remaining Korean-PII misses are bare names in messenger logs, author lines and
romanized form — list the people you know in `names` (see Configuration). The
0.2.0 changes that matter most — reading inside documents, git history, the
names list — are not line-level and do not show up in these tables at all.

`heldout2` (51 secrets, 36 Korean PII, 22 infra, 75 hard negatives), 0.1.0:

| Tool | Secrets | Korean PII | Infra | False positives |
| --- | --- | --- | --- | --- |
| **leakgate** (rules frozen) | **46** | 27 | **18** | 2 |
| **leakgate** (current, after real-world FP hardening) | 43 | 27 | 17 | **1** |
| gitleaks 8.30.1 | 32 | 0 | 0 | 1 |
| neuralyzer | 35 | 0 | 0 | 5 |
| detect-secrets 1.5.0 | 23 | 0 | 0 | 4 |
| Presidio 2.2.364 (+KR recognizers) | 28 | 30 | 18 | 35 |
| ko-pii 1.16.0 | 10 | **32** | 8 | 13 |
| maskingtape 0.3.0 (rules only) | 8 | 27 | 0 | 3 |

Read it plainly: leakgate leads on secrets and infra with the fewest false
positives, but **ko-pii is better at Korean PII**. Add it as an engine
(`--engine ko-pii`) when PII recall matters more than noise. The FP hardening
came from scanning 90 000 real site-packages files (floats read as card
numbers, `result_key: "Name"` read as credentials) and cost three `heldout2`
detections — a trade we chose deliberately. (0.1.0's known gaps — plates,
student/employee IDs, Kakao/공공데이터포털/Airtable/Docker Hub keys — are rules in 0.2.0.)

> **Windows note:** detect-secrets reads files with the locale codec, so on a
> Korean Windows it silently reports **nothing** for any UTF-8 file containing
> Hangul. Run it with `PYTHONUTF8=1`.

## Usage

```bash
leakgate scan PATH...                    # text report, exit 0 clean / 1 findings / 2 error
leakgate scan --history .                # every line the git history ever added
leakgate scan --history --rev origin/main..HEAD .   # only what you are about to push
leakgate hook install                    # pre-push hook: block a push that adds a leak
leakgate scan . --format sarif > r.sarif # for GitHub code scanning
leakgate scan - < transcript.jsonl       # stdin
leakgate scan . --known-secrets ~/.secrets/secrets.json
leakgate scan . --engine gitleaks --engine ko-pii   # fails closed if an engine is missing
leakgate redact ~/.claude/projects --apply --backup  # mask agent transcripts
leakgate init                            # write a commented .leakgate.toml
```

### Documents: Word, Excel, PowerPoint, HWPX, OpenDocument, PDF, images

A manuscript leaks where nobody looks, so container files are opened, not
skipped. From `.docx/.xlsx/.pptx/.hwpx/.odt` leakgate reads the body, **tracked
deletions** (text you deleted is still in the file), comments, headers and
footers, footnotes, speaker notes, chart data, embedded workbooks, and the
**author fields** (document properties, tracked-change and comment authors) —
every named author is reported as `document-author`. Findings say where:
`paper.docx [word/comments.xml]:1:9`.

PDFs need `pip install "leakgate[pdf]"` (pages, annotations, metadata). Images
are read only with `--ocr` (needs the `tesseract` binary, `kor+eng`).

A file that can hold text but cannot be read — legacy `.doc/.hwp/.xls`, an
archive, a scanned PDF with no text layer, a PDF whose Korean encoding pypdf
cannot decode, an Office lock file `~$…` (it stores the editor's user name) —
is listed as `UNSCANNED` and the run exits **2**. Pass `--allow-unscanned` to
accept that knowingly. Redaction never rewrites a container: fix it in the
application that made it.

Redaction keeps files usable: `C:\Users\<you>\proj` becomes
`C:\Users\<USER>\proj`, a key becomes `[REDACTED:github-token]`. It never opens
binaries, writes atomically, refuses to write a JSON/JSONL file that would stop
parsing, and backs up raw bytes (not decoded text) when asked. Suppress a
reviewed line with `leakgate:allow` in a comment, or add regexes to `allow`.

### pre-commit

```yaml
- repo: https://github.com/jahyunlee00299/leakgate
  rev: main
  hooks:
    - id: leakgate
```

### Configuration (`.leakgate.toml`)

```toml
categories = ["secret", "pii", "infra", "custom"]
engines = []                   # "gitleaks", "maskingtape", "ko-pii"
known_secrets = []             # files whose values are your real secrets
exclude = ["**/fixtures/**"]
allow = []                     # regexes; matching values are dropped

[custom]
terms = ["project-falcon"]     # codenames, private repo names
patterns = ['\bZq[A-Z]{2}DH\b']
metrics = ["yield", "titer"]   # flag a number within 40 chars of these
names = ["김민준", "Jane Roe"]  # people you know: matched anywhere, even in bare prose
names_files = ["people.txt"]   # one name per line, e.g. exported from a contact list
```

Rules need a cue to find a name (`교수님`, `참석자:`); the people who actually
leak from a lab's files are a known set, so `names` matches them anywhere:
`김민준이 어제 보냈다`, `김 민준`, `담당은 김민준이다`, and for Latin names the
reorderings `Kim Minjun`, `Kim, Minjun`, `M. Kim`, `Kim, M.`. A Korean name
followed by anything but a particle, the copula or a title is left alone, so
`김민준호` (someone else) and `정민수` do not match `김민준` / `정민`.

## Scope and limits

A secret removed in a later commit is still in every clone. `scan --history`
reads what each commit **added** (so a value is reported once, at the commit
that introduced it, with its line number there), including documents committed
and later deleted. `hook install` adds a pre-push hook that scans only the
outgoing commits; pass hook options with `--scan-args="--known-secrets ~/s.json"`.
Finding a leak in history means rewriting it (git-filter-repo) **and revoking
the credential** — redaction is never a substitute for rotation. Name
detection is rule-based (titles, labels, lists): a bare name in running prose
is not caught unless it is in your `names` list.

## 한국어 요약

공개 전에 레포·노트북·AI 에이전트 로그에서 **API 키, 한국 개인정보(주민번호·전화·계좌·주소·이름),
로컬 사용자명·내부 IP, 조직의 미공개 용어**를 한 번에 찾고 가립니다. 외부 의존성 없이 동작하며,
gitleaks·maskingtape·ko-pii를 추가 엔진으로 붙일 수 있습니다. 벤치마크에서 시크릿·인프라는
가장 높고 오탐은 가장 적지만, 한국어 PII 재현율은 ko-pii가 더 높습니다(위 표 참고).
git 히스토리는 검사하지 않으며, 유출된 키는 가리는 것만으로 안전해지지 않으니 반드시 폐기·재발급하세요.

## License

MIT

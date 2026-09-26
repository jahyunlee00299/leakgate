# Feature connectivity ledger

One entry per delivered unit: scope, layer, inputs/outputs, evidence, refutation, deferred risk.

## 0.1.0 — scanner core (core)
- **In/out**: paths or stdin → detectors → findings → text/json/sarif; exit 0/1/2.
- **Evidence**: `tests/test_leakgate.py` (43 cases: catches, ignores, CLI, SARIF, dogfood).
- **Refutation**: two blind corpora written by agents that never read the rules
  (`bench/heldout*.py`); 90 000-file site-packages scan for false positives;
  pathological 60 000-char lines for regex backtracking.
- **Found and fixed by refutation**: quadratic backtracking in the assignment rule
  (1.2 s per long line → linear); float digits read as cards/RRNs (11 k FPs);
  dict keys `result_key: "Name"` read as credentials; RFC 5737 doc IPs read as
  private; multi-line entries mis-scored by the benchmark harness itself.
- **Deferred**: names in free prose, messenger logs and author lines; vehicle
  plates; prefix-less vendor tokens (Kakao, data.go.kr, Airtable, Docker Hub).

## 0.1.0 — redaction (core)
- **In/out**: findings → in-place rewrite; `--backup` keeps raw bytes.
- **Evidence**: JSONL stays parseable and re-scans clean; binary untouched;
  CRLF preserved; stale span raises instead of guessing.
- **Deferred**: git history is out of scope (documented in README).

## 0.1.0 — engines (sub-feature)
- gitleaks / maskingtape / ko-pii adapters; a requested but missing engine
  fails closed (exit 2) unless `--allow-missing-engines`.
- **Evidence**: `test_missing_engine_fails_closed`; benchmark row
  `leakgate+gitleaks+maskingtape`.

## 0.1.0 — custom dictionary and known values (sub-feature)
- Terms / patterns / metric-number rules from `.leakgate.toml`; nothing private
  is hard-coded. Known values from json/.env/lines, never printed.
- **Evidence**: `test_custom_dictionary_is_config_only`,
  `test_known_values_matched_and_never_printed`.

## 0.2.0 — container formats (core)
- **In/out**: `.docx/.xlsx/.pptx/.hwpx/.odt/.ods/.odp` (stdlib zip + XML), PDF (optional
  pypdf), images (optional tesseract, `--ocr`) → segments `(where, text)` → the same
  detectors; `Finding.where` names the part; authors → `document-author`.
- **Fail-closed**: unreadable/opaque formats, scanned PDFs, partly-decoded PDFs
  (pypdf `/UniKS-UTF16-H`), Office lock files → `UNSCANNED`, exit 2 unless
  `--allow-unscanned`. Images without `--ocr` are a note, not a failure.
- **Evidence**: `tests/test_containers.py` (17 cases: tracked deletion, comments, footer,
  core properties, split runs, embedded xlsx, xlsx/pptx/odt, PDF text/metadata,
  no-text-layer, missing reader, 6 unreadable formats, OCR missing, redact refusal,
  clean doc, XML entity bomb refused by expat).
- **Refutation**: four mutations (no deleted text / no author attrs / no embedded parts /
  no text-layer check) each turned one test red. Real files: 217 documents in a
  Downloads folder (180 PDF, 14 docx, 14 xlsx, 7 hwp, 2 pptx) — 0 crashes; exposed two
  false positives in OLD rules (bare 13-digit numbers accepted as RRN on the gender
  digit alone; a card number cut out of a longer digit run) and pypdf's silent partial
  decode of Korean CMaps. All three fixed, pinned in tests; benchmark sets unchanged
  (dev 22/14/8/6 FP 0, heldout2 43/27/17 FP 1).
- **Deferred**: legacy `.hwp/.doc/.xls` readers (OLE compound files; reported
  UNSCANNED); OCR of scanned PDFs; EXIF/GPS metadata in photos; a 40 MB PDF takes ~2 min.

## 0.2.0 — known people (sub-feature)
- **In/out**: `[custom] names` + `names_files` (one name per line, `#` comments) →
  `PeopleDetector` → `pii/known-person`; redacts to `[PII:known-person]` with the
  particle kept.
- **Evidence**: `tests/test_people.py` (18 cases: bare prose, copula, spaced surname,
  compound surname, 2-syllable + particle, lists, Latin reorderings and case, names_files,
  redaction, 2 000-name speed; must-not: `정민수`, `공정민감도`, `김민준호`,
  `Kimberly Minjunson`, `Mkim.dev`).
- **Refutation**: first version failed its own tests twice — an unbounded 3-syllable
  match took `김민준호` for `김민준`, and `\w` boundaries (which count Hangul) missed
  `J. Roe에게`. Both fixed; removing either guard turns a test red. Real files with a
  30-name list: 1 610 hits, all at tab/comma/end-of-line/particle boundaries, none
  inside a longer word.
- **Deferred**: a 2-syllable name that is also a common noun (`하늘이`) still matches;
  given-name-only mentions (`민준이가`) need the given name listed separately.

## 0.2.0 — git history and pre-push hook (sub-feature)
- **In/out**: `scan --history [--rev RANGE] REPO` → `git log -p --unified=0` → added lines
  per (commit, file) → detectors; `where = "commit <sha10>"`, line = line number in that
  version. Document blobs (by extension, whatever git calls them) → `git show` → extract.
  `hook install` writes `.git/hooks/pre-push` that runs `--history --rev <remote>..<local>`.
- **Evidence**: `tests/test_history.py` (6 cases): a key deleted in a later commit is found
  once at its commit and line; `--rev` limits scope; a docx committed then deleted is
  extracted; Korean path; empty repo = 0, non-repo = 2; **end-to-end push to a bare remote
  is blocked and the remote keeps its old head**; a foreign hook is never clobbered
  without `--force`.
- **Refutation**: an uncompressed docx diffed as text made git's binary flag wrong —
  documents now go through the extractor by extension. `REMAINDER` swallowed `--force`
  (replaced by `--scan-args=`). Mutations (hook ignores the exit code / no document
  extraction) each fail a test. Real repos: 72 commits in 2 s; 4 077 commits in 149 s.
- **Deferred**: reachable-but-unreferenced objects (reflog, dangling) are not scanned;
  history rewriting itself is left to git-filter-repo.

## 0.2.0 — rules for the documented gaps (sub-feature)
- **Added**: `docker-hub-token` (`dckr_pat_`/`dckr_oat_`), `airtable-token` (`pat…​.…`),
  `kakao-api-key` and `data-go-kr-service-key` (no prefix: only with their name or
  `serviceKey=` nearby), `kr-vehicle-plate` (middle syllable limited to the ones plates
  use; optional province), `kr-student-employee-id` (학번/사번/직번/교번/student/employee id).
- **Evidence**: 9 must-catch and 8 must-not lines in `tests/test_leakgate.py`
  (`3층 1234호`, `12가지 1234개`, `Kakao Maps SDK v2.1.0`, `os.environ['KAKAO_REST_KEY']`,
  a placeholder serviceKey, an empty 학번 field, `patient 12345`).
- **Refutation**: 0 hits from the six new rules across 7 510 real files (210 documents,
  7 300 code/text files in four repositories and the script folder).
- **Honesty note**: heldout2 rose to 45/30/17 (FP 1) — but these rules came from the
  gap list heldout2 itself produced, so heldout2 is no longer blind for them. The
  honest number needs a new blind set (heldout3).

## 0.2.0 — honest measurement (cross-cutting)
- **heldout3** (`bench/heldout3.py`, 270 lines): written by a separate agent told not to
  read src/tests/README/docs/other sets (it reported reading nothing but listing the
  repo root to find `bench/`). Run once with the 0.2.0 rules frozen:
  **49/60 secrets, 46/70 Korean PII, 23/30 infra, 0/110 FP**; 0.1.0 on the same set:
  49/44/23/0.
- **Then tuned on it** (so no longer blind): `pypi-token`, `discord-webhook`,
  `session-cookie`, hyphenated `kr-student-employee-id` → 55/48/23/0. The four rules
  hit 0 of 7 532 real code/text files; `pypi-token` found all 10 real PyPI tokens in a
  live agent transcript.
- **Not done, deliberately**: `ko-pii` is NOT auto-enabled when installed — a gate whose
  result depends on what happens to be installed is not reproducible between machines;
  it stays `--engine ko-pii`.
- **Deferred**: unlisted names (messenger/author/romanized: 17 misses), health-insurance
  numbers, cloud tenants beyond OneDrive/SharePoint (4 misses), usernames in some path
  shapes (2). A heldout4 is needed before any of these are tuned.

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

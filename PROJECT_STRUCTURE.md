# Project structure

```
src/leakgate/
  cli.py            scan / redact / init; exit codes 0 clean, 1 findings, 2 error
  scanner.py        builds detectors from config, walks files, suppression, dedupe
  redact.py         span replacement with JSON/JSONL, binary and atomic-write guards
  report.py         text / json / sarif renderers (never print raw values)
  config.py         .leakgate.toml loading
  placeholder.py    documentation-filler discrimination shared by secret rules
  finding.py        the Finding record and masking
  detectors/
    base.py         rule scanning + per-rule substring gates
    secrets.py      vendor tokens and keyword assignments
    kr_pii.py       Korean PII + email/card
    infra.py        home-path usernames, tenants, private IPs, internal hosts
    custom.py       organisation dictionary (terms / patterns / metric-number)
    known_values.py literal matching of the user's own secret values
    external.py     optional gitleaks / maskingtape / ko-pii adapters
bench/              corpora (dev, heldout, heldout2) and run.py
tests/              contract tests; credential-shaped values generated at runtime
docs/               feature-connectivity ledger
```

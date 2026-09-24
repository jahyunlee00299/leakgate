"""Command line: `leakgate scan`, `leakgate redact`, `leakgate init`.

Exit codes: 0 = clean, 1 = findings (scan) / files changed (redact dry-run),
2 = usage or runtime error. A requested engine that is unavailable makes the
run fail with 2 unless --allow-missing-engines is given: a gate that silently
ran with fewer checks than you asked for is not a gate.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from leakgate import __version__, config as cfgmod, report
from leakgate.redact import UnsafeRedaction, redact_file
from leakgate.scanner import Scanner


def _setup_stdio() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="+", help="files or directories ('-' reads stdin for scan)")
    p.add_argument("--config", help=f"path to config (default: nearest {cfgmod.CONFIG_NAME})")
    p.add_argument("--known-secrets", action="append", default=[], metavar="FILE",
                   help="file whose values are your real secrets (json/.env/lines); repeatable")
    p.add_argument("--engine", action="append", default=[], metavar="NAME",
                   help="extra engine: gitleaks, maskingtape, ko-pii; repeatable")
    p.add_argument("--category", action="append", default=[], metavar="CAT",
                   help="restrict to secret/pii/infra/custom; repeatable")
    p.add_argument("--allow-missing-engines", action="store_true")


def _build(args) -> Scanner:
    first = Path(args.paths[0]) if args.paths[0] != "-" else None
    cfg = cfgmod.load(args.config, search_from=first)
    if args.engine:
        cfg.engines = sorted(set(cfg.engines) | set(args.engine))
    if args.category:
        cfg.categories = args.category
    sc = Scanner(cfg, extra_known=args.known_secrets)
    if sc.unavailable and not args.allow_missing_engines:
        raise SystemExit("leakgate: requested engine unavailable — " + "; ".join(sc.unavailable)
                         + " (use --allow-missing-engines to continue without it)")
    return sc


def cmd_scan(args) -> int:
    sc = _build(args)
    if args.paths == ["-"]:
        findings, n = sc.scan_text(sys.stdin.read(), "<stdin>"), 1
    else:
        findings, n = sc.scan_paths(args.paths)
    print(report.RENDERERS[args.format](findings, n, sc.unavailable))
    return 1 if findings else 0


def cmd_redact(args) -> int:
    sc = _build(args)
    findings, n = sc.scan_paths(args.paths)
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.path].append(f)
    failed = 0
    for path, fs in sorted(by_file.items()):
        if not args.apply:
            print(f"would redact {len(fs):>4}  {path}")
            continue
        try:
            print(f"redacted     {redact_file(path, fs, backup=args.backup):>4}  {path}")
        except (UnsafeRedaction, UnicodeDecodeError) as e:
            failed += 1
            print(f"SKIPPED            {path}: {e}", file=sys.stderr)
    total = sum(len(v) for v in by_file.values())
    mode = "applied" if args.apply else "dry-run"
    print(f"\nleakgate redact ({mode}): {total} span(s) in {len(by_file)} of {n} file(s)"
          + (f", {failed} file(s) skipped as unsafe" if failed else ""))
    if args.apply:
        left, _ = sc.scan_paths([p for p in by_file])
        print(f"leakgate redact: {len(left)} finding(s) remain after re-scan")
        return 2 if failed or left else 0
    return 1 if total else 0


def cmd_init(args) -> int:
    target = Path(args.dir) / cfgmod.CONFIG_NAME
    if target.exists():
        print(f"{target} already exists; not overwritten", file=sys.stderr)
        return 2
    target.write_text(cfgmod.SAMPLE, encoding="utf-8")
    print(f"wrote {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _setup_stdio()
    ap = argparse.ArgumentParser(prog="leakgate",
                                 description="Pre-publish gate for secrets, Korean PII, "
                                             "local paths and private project terms.")
    ap.add_argument("--version", action="version", version=f"leakgate {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="report findings (read-only)")
    _common(s)
    s.add_argument("--format", choices=sorted(report.RENDERERS), default="text")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("redact", help="replace findings in place (dry-run unless --apply)")
    _common(r)
    r.add_argument("--apply", action="store_true")
    r.add_argument("--backup", action="store_true", help="keep <file>.leakgate.bak (raw bytes)")
    r.set_defaults(func=cmd_redact)
    i = sub.add_parser("init", help=f"write a sample {cfgmod.CONFIG_NAME}")
    i.add_argument("dir", nargs="?", default=".")
    i.set_defaults(func=cmd_init)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as e:
        print(f"leakgate: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

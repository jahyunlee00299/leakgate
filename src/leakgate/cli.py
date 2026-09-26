"""Command line: `leakgate scan`, `leakgate redact`, `leakgate init`.

Exit codes: 0 = clean, 1 = findings (scan) / files changed (redact dry-run),
2 = usage or runtime error. A requested engine that is unavailable makes the
run fail with 2 unless --allow-missing-engines is given: a gate that silently
ran with fewer checks than you asked for is not a gate.
"""
from __future__ import annotations

import argparse
import shlex
import sys
from collections import defaultdict
from pathlib import Path

from leakgate import __version__, config as cfgmod, history, report
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
    p.add_argument("--ocr", action="store_true", help="read images with tesseract (kor+eng)")
    p.add_argument("--allow-unscanned", action="store_true",
                   help="do not fail (exit 2) on files that hold text leakgate cannot read")


def _build(args) -> Scanner:
    first = Path(args.paths[0]) if args.paths[0] != "-" else None
    cfg = cfgmod.load(args.config, search_from=first)
    if args.engine:
        cfg.engines = sorted(set(cfg.engines) | set(args.engine))
    if args.category:
        cfg.categories = args.category
    sc = Scanner(cfg, extra_known=args.known_secrets, ocr=args.ocr)
    if sc.unavailable and not args.allow_missing_engines:
        raise SystemExit("leakgate: requested engine unavailable — " + "; ".join(sc.unavailable)
                         + " (use --allow-missing-engines to continue without it)")
    return sc


def cmd_scan(args) -> int:
    sc = _build(args)
    if args.paths == ["-"]:
        findings, n = sc.scan_text(sys.stdin.read(), "<stdin>"), 1
    elif args.history:
        findings, n = [], 0
        for repo in args.paths:
            f, k = history.scan_history(sc, Path(repo), shlex.split(args.rev) if args.rev else None)
            findings, n = findings + f, n + k
    else:
        findings, n = sc.scan_paths(args.paths)
    print(report.RENDERERS[args.format](findings, n, sc.unavailable, sc.unscanned, sc.images_skipped))
    if sc.unscanned and not args.allow_unscanned:
        print(f"leakgate: {len(sc.unscanned)} file(s) could not be read — failing closed "
              "(--allow-unscanned to accept)", file=sys.stderr)
        return 2
    return 1 if findings else 0


def cmd_redact(args) -> int:
    sc = _build(args)
    findings, n = sc.scan_paths(args.paths)
    by_file = defaultdict(list)
    for f in findings:
        if not f.where:
            by_file[f.path].append(f)
    for path in sorted({f.path for f in findings if f.where}):
        print(f"cannot redact inside {path} — fix it in the source application", file=sys.stderr)
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
        left, _ = sc.scan_paths(list(by_file)) if by_file else ([], 0)
        left = [f for f in left if not f.where]
        print(f"leakgate redact: {len(left)} finding(s) remain after re-scan")
        return 2 if failed or left else 0
    return 1 if total else 0


def cmd_hook(args) -> int:
    hook = history.install_hook(Path(args.repo), shlex.split(args.scan_args), force=args.force)
    print(f"wrote {hook} — pushes are scanned for what they add (bypass once: git push --no-verify)")
    return 0


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
    s.add_argument("--history", action="store_true",
                   help="scan every line the git history ever added (PATHS are repositories)")
    s.add_argument("--rev", help="with --history: revisions to scan, as for `git log` "
                                 "(default: all refs), e.g. 'origin/main..HEAD'")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("redact", help="replace findings in place (dry-run unless --apply)")
    _common(r)
    r.add_argument("--apply", action="store_true")
    r.add_argument("--backup", action="store_true", help="keep <file>.leakgate.bak (raw bytes)")
    r.set_defaults(func=cmd_redact)
    h = sub.add_parser("hook", help="install a git pre-push hook that scans outgoing commits")
    h.add_argument("action", choices=["install"])
    h.add_argument("repo", nargs="?", default=".")
    h.add_argument("--force", action="store_true", help="replace a pre-push hook leakgate did not write")
    h.add_argument("--scan-args", default="",
                   help="extra `scan` options for the hook, e.g. --scan-args=\"--known-secrets ~/s.json\" (use =)")
    h.set_defaults(func=cmd_hook)
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

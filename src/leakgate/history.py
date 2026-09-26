"""Scan what a repository's history ever added, not just what is in the tree.

A key deleted in a later commit is still in every clone. Only ADDED lines are
scanned, so a value is reported once — at the commit that introduced it — with
the commit and the line number it had in that version of the file. Binary
blobs that are documents (docx/pdf/…) are extracted like files on disk.

`install_hook` writes a pre-push hook that scans only the commits being pushed.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from leakgate import extract
from leakgate.finding import Finding

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
HOOK_MARK = "# installed by leakgate"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=false", *args],
                          capture_output=True)


def added_lines(repo: Path, rev: list[str]):
    """Yield (commit, path, [(new_lineno, text)], binary) for every file a commit touched."""
    r = _git(repo, "log", *rev, "-p", "--no-color", "--no-ext-diff", "--unified=0", "--no-renames",
             "--format=%x00commit %H")
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip() or "git log failed")
    commit, path, lines, binary, lineno = "", "", [], False, 0

    def flush():
        if commit and path and (lines or binary):
            return (commit, path, lines, binary)
        return None

    for raw in r.stdout.decode("utf-8", "replace").split("\n"):
        if raw.startswith("\x00commit "):
            if (item := flush()):
                yield item
            commit, path, lines, binary = raw.split()[1], "", [], False
        elif raw.startswith("diff --git "):
            if (item := flush()):
                yield item
            path, lines, binary = "", [], False
        elif raw.startswith("+++ "):
            path = "" if raw[4:] == "/dev/null" else raw[4:].removeprefix("b/")
        elif raw.startswith("Binary files ") and raw.endswith(" differ"):
            m = re.search(r" and (?:b/)?(.+) differ$", raw)
            if m and m.group(1) != "/dev/null":
                path, binary = m.group(1), True
        elif (m := HUNK.match(raw)):
            lineno = int(m.group(1))
        elif raw.startswith("+") and path:
            lines.append((lineno, raw[1:]))
            lineno += 1
    if (item := flush()):
        yield item


def scan_history(scanner, repo: Path, rev: list[str] | None = None) -> tuple[list[Finding], int]:
    """Findings from every added line in `rev` (default: all refs). Returns (findings, blobs)."""
    repo = Path(repo)
    findings: list[Finding] = []
    n = 0
    for commit, path, lines, binary in added_lines(repo, rev or ["--all"]):
        n += 1
        where = f"commit {commit[:10]}"
        shown = f"{repo / path}"
        if extract.kind(Path(path)):
            # A document is read through its extractor whatever git thinks of it:
            # an uncompressed zip diffs as "text", and scanning that raw is wrong.
            if not (Path(path).suffix.lower() in extract.IMAGES and not scanner.ocr):
                findings += _scan_blob(scanner, repo, commit, path, shown, where)
            continue
        if binary:
            continue
        text = "\n".join(t for _, t in lines)
        for f in scanner.scan_text(text, shown, where):
            findings.append(replace(f, line=lines[f.line - 1][0]))
    return findings, n


def _scan_blob(scanner, repo: Path, commit: str, path: str, shown: str, where: str) -> list[Finding]:
    blob = _git(repo, "show", f"{commit}:{path}")
    if blob.returncode != 0:
        return []
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d) / Path(path).name
        tmp.write_bytes(blob.stdout)
        ex = extract.extract(tmp, ocr=scanner.ocr)
    if ex.unscanned:
        scanner.unscanned.append((f"{shown} @ {commit[:10]}", ex.unscanned))
    out = []
    for part, text in ex.segments:
        out += scanner.scan_text(text, shown, f"{where} {part}")
    return out


HOOK = """#!/bin/sh
{mark}
# Scans only the commits being pushed; blocks the push on any finding.
# Bypass once with: git push --no-verify
z=0000000000000000000000000000000000000000
status=0
while read local_ref local_sha remote_ref remote_sha; do
  [ "$local_sha" = "$z" ] && continue
  if [ "$remote_sha" = "$z" ]; then
    rev="$local_sha --not --remotes"
  else
    rev="$remote_sha..$local_sha"
  fi
  "{python}" -m leakgate scan --history --rev "$rev" {extra} . || status=1
done
exit $status
"""


def install_hook(repo: Path, extra: list[str], force: bool = False) -> Path:
    r = _git(Path(repo), "rev-parse", "--git-path", "hooks")
    if r.returncode != 0:
        raise RuntimeError(f"{repo} is not a git repository")
    hooks = Path(repo) / r.stdout.decode().strip()
    hook = hooks / "pre-push"
    if hook.exists() and HOOK_MARK not in hook.read_text(encoding="utf-8", errors="replace") and not force:
        raise RuntimeError(f"{hook} exists and was not written by leakgate (use --force to replace)")
    hooks.mkdir(parents=True, exist_ok=True)
    python = Path(sys.executable).as_posix()
    hook.write_text(HOOK.format(mark=HOOK_MARK, python=python,
                                extra=" ".join(shlex.quote(a) for a in extra)), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    return hook

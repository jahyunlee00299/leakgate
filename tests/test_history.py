"""Git history scanning and the pre-push hook, on throwaway repositories."""
from __future__ import annotations

import os
import random
import shutil
import string
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from leakgate.cli import main  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
rng = random.Random(11)
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid",
       "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")}


def tok(n):
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(n))


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=ENV)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    return r


def commit(repo: Path, files: dict[str, str | bytes | None], msg: str) -> str:
    for name, body in files.items():
        p = repo / name
        if body is None:
            p.unlink()
        elif isinstance(body, bytes):
            p.write_bytes(body)
        else:
            p.write_text(body, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def run(capsys, *argv) -> tuple[int, str]:
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_deleted_secret_is_still_found(repo, capsys):
    key = f"ghp_{tok(36)}"
    c1 = commit(repo, {"a.py": f"x = 1\ny = 2\nTOKEN = '{key}'\n"}, "add")
    commit(repo, {"a.py": "x = 1\ny = 2\n"}, "remove the key")
    assert run(capsys, "scan", str(repo))[0] == 0                   # working tree is clean
    rc, out = run(capsys, "scan", "--history", str(repo))
    assert rc == 1 and f"[commit {c1[:10]}]:3:" in out and "github-token" in out
    assert key not in out
    assert out.count("github-token") == 1                           # reported once, where it was added


def test_rev_range_limits_the_scan(repo, capsys):
    commit(repo, {"old.txt": f"ghp_{tok(36)}\n"}, "old")
    base = git(repo, "rev-parse", "HEAD")
    commit(repo, {"new.txt": "연락처 010-2345-6789\n"}, "new")
    rc, out = run(capsys, "scan", "--history", "--rev", f"{base}..HEAD", str(repo))
    assert rc == 1 and "kr-mobile" in out and "github-token" not in out


def test_document_in_history_is_extracted(repo, capsys):
    buf = repo / "paper.docx"
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                   'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>tel 010-2345-6789</w:t>'
                   '</w:r></w:p></w:body></w:document>')
    commit(repo, {}, "add docx")
    commit(repo, {"paper.docx": None}, "drop docx")
    rc, out = run(capsys, "scan", "--history", str(repo))
    assert rc == 1 and "word/document.xml]" in out and "kr-mobile" in out
    assert out.count("kr-mobile") == 1                  # the deletion commit adds nothing


def test_non_ascii_path_and_non_repo(repo, tmp_path, capsys):
    assert run(capsys, "scan", "--history", str(repo))[0] == 0      # no commits: genuinely nothing
    plain = tmp_path / "plain"
    plain.mkdir()
    assert run(capsys, "scan", "--history", str(plain))[0] == 2     # not a repository: error, not "clean"
    commit(repo, {"보고서.txt": "담당자: 한서연\n"}, "korean path")
    rc, out = run(capsys, "scan", "--history", str(repo))
    assert rc == 1 and "보고서.txt" in out


def test_pre_push_hook_blocks_a_leaking_push(repo, tmp_path, capsys):
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, env=ENV)
    git(repo, "remote", "add", "origin", str(remote))
    commit(repo, {"ok.txt": "nothing here\n"}, "clean")
    assert run(capsys, "hook", "install", str(repo), "--scan-args=--allow-unscanned")[0] == 0
    hook = repo / ".git" / "hooks" / "pre-push"
    assert "--allow-unscanned" in hook.read_text(encoding="utf-8")
    assert "installed by leakgate" in hook.read_text(encoding="utf-8")

    push = lambda: subprocess.run(["git", "-C", str(repo), "push", "-q", "origin", "main"],  # noqa: E731
                                  capture_output=True, text=True, encoding="utf-8", env=ENV)
    first = push()
    assert first.returncode == 0, first.stderr + first.stdout      # clean history goes through

    commit(repo, {"leak.txt": f"ghp_{tok(36)}\n"}, "leak")
    blocked = push()
    assert blocked.returncode != 0 and "github-token" in (blocked.stdout + blocked.stderr)
    assert git(remote, "log", "--oneline", "main").count("\n") == 0   # remote still has 1 commit


def test_hook_refuses_to_clobber_a_foreign_hook(repo, capsys):
    hook = repo / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    assert main(["hook", "install", str(repo)]) == 2
    assert hook.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert main(["hook", "install", str(repo), "--force"]) == 0

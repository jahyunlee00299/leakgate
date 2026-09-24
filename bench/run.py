"""Line-level benchmark: leakgate vs. prior-art scanners on bench/corpus.py.

A detector "hits" a line if it reports anything on it. Output: recall per
category and false positives on the NEG lines. Competitors are optional and
are skipped (with a note) when not installed:

  gitleaks        binary on PATH (or $GITLEAKS)
  neuralyzer      $NEURALYZER = path to neuralyzer.py
  detect-secrets, maskingtape, ko-pii, presidio-analyzer   pip packages

Run:  python bench/run.py [--json out.json]
Note: set PYTHONUTF8=1 on Windows, or detect-secrets reads the UTF-8 corpus
with the locale codec and silently reports nothing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

import corpus as _c  # noqa: E402
import heldout as _h  # noqa: E402
import heldout2 as _h2  # noqa: E402
from leakgate import config as cfgmod  # noqa: E402
from leakgate.scanner import Scanner  # noqa: E402

CATS = ["SECRET", "KR_PII", "INFRA", "RESEARCH"]


def _entry_hits(entries, hit_lines):
    """Map 1-based hit line numbers of the joined text back to entries.

    Entries can span several lines (a YAML block, a two-line .env), so an
    entry counts as hit when ANY of its lines is hit. Scoring by raw line
    index would shift every later entry after the first multi-line one.
    """
    out, line = [], 1
    for e in entries:
        n = len(e.splitlines()) or 1     # same line splitting the scanners use
        out.append(any(ln in hit_lines for ln in range(line, line + n)))
        line += n
    return out


def _lines_via_file(lines, fn):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "corpus.txt"
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return fn(f)


def leakgate_detector(engines=()):
    def run(lines):
        cfg = cfgmod.load(HERE / "leakgate-bench.toml")
        cfg.engines = list(engines)
        sc = Scanner(cfg)
        if sc.unavailable:
            raise RuntimeError("; ".join(sc.unavailable))
        return _entry_hits(lines, {f.line for f in sc.scan_text("\n".join(lines))})
    return run


def gitleaks(lines):
    exe = os.environ.get("GITLEAKS") or shutil.which("gitleaks")
    if not exe:
        raise RuntimeError("gitleaks not on PATH")

    def go(f):
        rep = f.parent / "r.json"
        subprocess.run([exe, "dir", str(f), "-f", "json", "-r", str(rep), "--no-banner", "-l", "error",
                        "--exit-code", "0"], check=True)
        hit = {ln for x in json.loads(rep.read_text() or "[]") for ln in range(x["StartLine"], x["EndLine"] + 1)}
        return _entry_hits(lines, hit)
    return _lines_via_file(lines, go)


def neuralyzer(lines):
    p = os.environ.get("NEURALYZER")
    if not p:
        raise RuntimeError("set NEURALYZER=path/to/neuralyzer.py")
    spec = importlib.util.spec_from_file_location("neuralyzer", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return [bool(m.find_secrets(t)) for t in lines]


def detect_secrets(lines):
    from detect_secrets import SecretsCollection
    from detect_secrets.settings import default_settings

    def go(f):
        sc = SecretsCollection()
        with default_settings():
            sc.scan_file(str(f))
        return _entry_hits(lines, {s.line_number for _, s in sc})
    return _lines_via_file(lines, go)


def maskingtape(lines):
    import maskingtape as mt
    p = mt.Pipeline()
    return [bool(p.scan(t)) for t in lines]


def ko_pii(lines):
    import ko_pii as kp
    return [bool(kp.detect_all(t)) for t in lines]


def presidio(lines):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    import presidio_analyzer.predefined_recognizers as pr
    nlp = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [
        {"lang_code": "en", "model_name": "en_core_web_sm"}]}).create_engine()
    eng = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    for cls in ("KrRrnRecognizer", "KrBrnRecognizer", "KrPassportRecognizer",
                "KrDriverLicenseRecognizer", "KrFrnRecognizer"):
        eng.registry.add_recognizer(getattr(pr, cls)(supported_language="en"))
    return [bool(eng.analyze(text=t, language="en", score_threshold=0.4)) for t in lines]


DETECTORS = {
    "leakgate": leakgate_detector(),
    "leakgate+gitleaks+maskingtape": leakgate_detector(("gitleaks", "maskingtape")),
    "gitleaks": gitleaks,
    "neuralyzer": neuralyzer,
    "detect-secrets": detect_secrets,
    "presidio(+KR)": presidio,
    "ko-pii": ko_pii,
    "maskingtape": maskingtape,
}


def evaluate(hits, C):
    row = {}
    for cat in CATS:
        idx = [i for i, c in enumerate(C) if c[0] == cat]
        row[cat] = [sum(hits[i] for i in idx), len(idx)]
    neg = [i for i, c in enumerate(C) if c[0] == "NEG"]
    row["FP"] = [sum(hits[i] for i in neg), len(neg)]
    row["missed"] = [f"{C[i][0]}/{C[i][1]}" for i in range(len(C)) if C[i][0] != "NEG" and not hits[i]]
    row["false_positives"] = [C[i][2][:80] for i in neg if hits[i]]
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--only", action="append")
    ap.add_argument("--set", choices=["dev", "heldout", "heldout2"], default="dev",
                    help="dev = corpus the rules were tuned on; heldout = blind set written without seeing the rules")
    args = ap.parse_args()
    C = {"dev": _c, "heldout": _h, "heldout2": _h2}[args.set].corpus()
    lines = [c[2] for c in C]
    results, skipped = {}, {}
    for name, fn in DETECTORS.items():
        if args.only and name not in args.only:
            continue
        t0 = time.perf_counter()
        try:
            hits = fn(lines)
        except Exception as e:
            skipped[name] = f"{type(e).__name__}: {e}"
            continue
        results[name] = evaluate(hits, C) | {"seconds": round(time.perf_counter() - t0, 2)}
    print(f"{'detector':32s}" + "".join(f"{c:>10s}" for c in CATS) + f"{'FP(NEG)':>10s}")
    for n, r in results.items():
        print(f"{n:32s}" + "".join(f"{r[c][0]:>5d}/{r[c][1]:<4d}" for c in CATS) + f"{r['FP'][0]:>5d}/{r['FP'][1]:<4d}")
    for n, why in skipped.items():
        print(f"skipped {n}: {why}")
    if args.json:
        Path(args.json).write_text(json.dumps({"results": results, "skipped": skipped},
                                              ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

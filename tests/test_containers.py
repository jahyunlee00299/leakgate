"""Container formats: what a manuscript hides outside its visible body text.

Fixtures are assembled at runtime from minimal OOXML/ODF parts, so no document
with personal data is ever committed. Names and numbers are fictional.
"""
from __future__ import annotations

import builtins
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

from leakgate import extract  # noqa: E402
from leakgate.cli import main  # noqa: E402
from leakgate.config import Config  # noqa: E402
from leakgate.scanner import Scanner  # noqa: E402

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
PHONE = "010-2345-6789"


def _zip(path: Path, parts: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, xml in parts.items():
            z.writestr(name, xml)
    return path


def docx(path: Path, **extra: str) -> Path:
    parts = {
        "[Content_Types].xml": "<Types/>",
        "word/document.xml": (
            f'<w:document {W}><w:body>'
            f'<w:p><w:r><w:t>clean opening sentence</w:t></w:r></w:p>'
            f'<w:p><w:r><w:t xml:space="preserve">call me at </w:t></w:r><w:r><w:t>{PHONE}</w:t></w:r></w:p>'
            f'<w:p><w:del w:author="Reviewer Kim"><w:r><w:delText>old contact jane.roe@corp-mail.kr</w:delText>'
            f'</w:r></w:del><w:ins w:author="이도윤"><w:r><w:t>new text</w:t></w:r></w:ins></w:p>'
            f'</w:body></w:document>'),
        "word/comments.xml": (
            f'<w:comments {W}><w:comment w:id="0" w:author="박서연" w:initials="PS">'
            f'<w:p><w:r><w:t>see C:\\Users\\jdoe\\data\\raw.csv</w:t></w:r></w:p></w:comment></w:comments>'),
        "word/footer1.xml": f'<w:ftr {W}><w:p><w:r><w:t>담당자: 한서연</w:t></w:r></w:p></w:ftr>',
        "docProps/core.xml": (
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Jane Roe</dc:creator>'
            '<cp:lastModifiedBy>python-docx</cp:lastModifiedBy></cp:coreProperties>'),
    }
    parts.update(extra)
    return _zip(path, parts)


def scan(path: Path, **kw):
    sc = Scanner(Config(), **kw)
    findings, n = sc.scan_paths([str(path)])
    return sc, findings


# ---- prove: every hiding place in a .docx ------------------------------------
def test_docx_hiding_places(tmp_path):
    _, fs = scan(docx(tmp_path / "paper.docx"))
    got = {(f.where, f.rule) for f in fs}
    assert ("word/document.xml", "kr-mobile") in got
    assert ("word/document.xml [tracked deletion]", "email") in got
    assert ("word/comments.xml", "windows-home-path") in got
    assert ("word/footer1.xml", "kr-name-labeled") in got
    assert ("docProps/core.xml [properties]", "document-author") in got
    authors = {f.value for f in fs if f.rule == "document-author"}
    assert {"Reviewer Kim", "이도윤", "박서연", "Jane Roe"} <= authors
    assert "python-docx" not in authors            # generator names are not people
    assert all(f.path.endswith("paper.docx") for f in fs)


def test_split_runs_are_joined(tmp_path):
    """Word splits text into runs at will; a number cut in two must still match."""
    doc = (f'<w:document {W}><w:body><w:p><w:r><w:t>010-23</w:t></w:r><w:r><w:t>45-6789</w:t></w:r>'
           f'</w:p></w:body></w:document>')
    _, fs = scan(_zip(tmp_path / "s.docx", {"word/document.xml": doc}))
    assert [f.rule for f in fs] == ["kr-mobile"]


def test_embedded_workbook_is_read(tmp_path):
    inner = tmp_path / "inner.xlsx"
    _zip(inner, {"xl/sharedStrings.xml": f'<sst><si><t>{PHONE}</t></si></sst>'})
    d = docx(tmp_path / "e.docx", **{"word/embeddings/Microsoft_Excel_Worksheet.xlsx": inner.read_bytes()})
    inner.unlink()
    _, fs = scan(d)
    assert any(f.where.startswith("word/embeddings/") and f.rule == "kr-mobile" for f in fs)


def test_xlsx_pptx_odt(tmp_path):
    x = _zip(tmp_path / "t.xlsx", {
        "xl/sharedStrings.xml": f'<sst><si><t>{PHONE}</t></si></sst>',
        "xl/worksheets/sheet1.xml": '<worksheet><sheetData><row><c t="s"><v>0</v></c>'
                                    '<c><v>12</v></c></row></sheetData></worksheet>',
        "xl/comments1.xml": '<comments><authors><author>Jane Roe</author></authors>'
                            '<commentList><comment><text><r><t>ask 한서연 씨</t></r></text></comment>'
                            '</commentList></comments>'})
    _, fs = scan(x)
    assert {"kr-mobile", "document-author", "kr-name-title"} <= {f.rule for f in fs}

    p = _zip(tmp_path / "t.pptx", {
        "ppt/slides/slide1.xml": '<sld><cSld><spTree><sp><txBody><p><r><t>clean</t></r></p></txBody></sp>'
                                 '</spTree></cSld></sld>',
        "ppt/notesSlides/notesSlide1.xml": f'<notes><p><r><t>speaker phone {PHONE}</t></r></p></notes>'})
    _, fs = scan(p)
    assert [(f.where, f.rule) for f in fs] == [("ppt/notesSlides/notesSlide1.xml", "kr-mobile")]

    o = _zip(tmp_path / "t.odt", {
        "mimetype": "application/vnd.oasis.opendocument.text",
        "content.xml": '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
                       'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text>'
                       f'<text:p>tel <text:span>{PHONE}</text:span> end</text:p></office:text></office:body>'
                       '</office:document-content>'})
    _, fs = scan(o)
    assert [f.rule for f in fs] == ["kr-mobile"]


# ---- PDF ---------------------------------------------------------------------------
def _pdf(path: Path, text: str | None) -> Path:
    """A one-page PDF; `text=None` gives a page with no text layer."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode() if text else b""
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info << /Author (Jane Roe) >> >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref)
    path.write_bytes(out)
    return path


def test_pdf_text_and_metadata(tmp_path):
    pytest.importorskip("pypdf")
    sc, fs = scan(_pdf(tmp_path / "a.pdf", f"contact {PHONE}"))
    assert ("page 1", "kr-mobile") in {(f.where, f.rule) for f in fs}
    assert sc.unscanned == []


def test_pdf_without_text_layer_fails_closed(tmp_path):
    pytest.importorskip("pypdf")
    p = _pdf(tmp_path / "scan.pdf", None)
    sc, _ = scan(p)
    assert sc.unscanned and "no text layer" in sc.unscanned[0][1]
    assert main(["scan", str(p)]) == 2
    assert main(["scan", str(p), "--allow-unscanned"]) in (0, 1)


def test_pdf_reader_missing_fails_closed(tmp_path, monkeypatch):
    real = builtins.__import__

    def no_pypdf(name, *a, **k):
        if name == "pypdf":
            raise ImportError("simulated")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_pypdf)
    sc, _ = scan(_pdf(tmp_path / "a.pdf", "x"))
    assert "not installed" in sc.unscanned[0][1]


# ---- refute: formats and states that must not pass silently ------------------------
@pytest.mark.parametrize("name,data", [
    ("legacy.doc", b"\xd0\xcf\x11\xe0" + b"\0" * 64),
    ("form.hwp", b"\xd0\xcf\x11\xe0" + b"\0" * 64),
    ("bundle.zip", b"PK\x05\x06" + b"\0" * 18),
    ("broken.docx", b"this is not a zip"),
    ("bad.xlsx", None),
    ("~$paper.docx", b"\x08jdoe-pc" + b"\0" * 100),       # Word lock file: holds the editor's name
])
def test_unreadable_fails_closed(tmp_path, name, data):
    p = tmp_path / name
    if data is None:
        _zip(p, {"xl/sharedStrings.xml": "<sst><si><t>unclosed"})
    else:
        p.write_bytes(data)
    assert main(["scan", str(p)]) == 2
    assert main(["scan", str(tmp_path), "--allow-unscanned"]) == 0


def test_images_need_ocr(tmp_path, monkeypatch, capsys):
    (tmp_path / "fig.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    assert main(["scan", str(tmp_path)]) == 0
    assert "not read (use --ocr)" in capsys.readouterr().out
    monkeypatch.setattr(extract.shutil, "which", lambda _: None)
    assert main(["scan", str(tmp_path), "--ocr"]) == 2


def test_redact_never_rewrites_a_container(tmp_path, capsys):
    d = docx(tmp_path / "paper.docx")
    raw = d.read_bytes()
    rc = main(["redact", str(tmp_path), "--apply"])
    assert d.read_bytes() == raw and rc == 0
    assert "cannot redact inside" in capsys.readouterr().err


def test_clean_docx_is_clean(tmp_path):
    doc = f'<w:document {W}><w:body><w:p><w:r><w:t>NADH (0.2 mM) was added</w:t></w:r></w:p></w:body></w:document>'
    sc, fs = scan(_zip(tmp_path / "c.docx", {"word/document.xml": doc,
                                              "word/styles.xml": "<styles>Arial</styles>"}))
    assert fs == [] and sc.unscanned == []


def test_entity_expansion_is_refused(tmp_path):
    bomb = ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
            + "".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">' for i in range(8))
            + f']><w:document {W}><w:body><w:p><w:r><w:t>&i;</w:t></w:r></w:p></w:body></w:document>')
    import time
    t = time.perf_counter()
    sc, _ = scan(_zip(tmp_path / "bomb.docx", {"word/document.xml": bomb}))
    assert time.perf_counter() - t < 5
    assert sc.unscanned and "ParseError" in sc.unscanned[0][1]      # refused, and said so

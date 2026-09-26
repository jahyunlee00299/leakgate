"""Text out of container formats: Office/OpenDocument/HWPX zips, PDF, images.

A manuscript leaks where nobody looks: a reviewer's name on a tracked change,
a deleted sentence that is still in the file, a comment, a footer, the author
field in document properties. Each is pulled out as its own *segment* with a
location (`word/comments.xml`, `page 3`, `metadata`) so a finding can say
where inside the file it sits.

A format that can carry text but cannot be read here (legacy .doc/.hwp, a
PDF without pypdf or without a text layer, an archive) is reported as
UNSCANNED, never skipped silently: a gate that passes what it could not open
is not a gate. Images are read only with OCR (`--ocr`), which needs the
`tesseract` binary.
"""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

OOXML = {".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".pptx", ".pptm"}
ODF = {".odt", ".ods", ".odp"}
HWPX = {".hwpx"}
PDF = {".pdf"}
IMAGES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp"}
# Can hold text, but no reader here: reported, never passed.
OPAQUE = {".doc", ".xls", ".ppt", ".hwp", ".rtf", ".zip", ".7z", ".rar", ".gz", ".tgz",
          ".bz2", ".xz", ".db", ".sqlite", ".sqlite3", ".msg", ".eml", ".pst"}
CONTAINERS = OOXML | ODF | HWPX | PDF | IMAGES | OPAQUE
MAX_CONTAINER_BYTES = 200 * 1024 * 1024
MAX_PART_BYTES = 50 * 1024 * 1024

_PART = re.compile(
    r"^(?:"
    r"word/(?:document|comments[^/]*|header\d*|footer\d*|footnotes|endnotes|people)\.xml"
    r"|word/charts/[^/]+\.xml"
    r"|xl/(?:sharedStrings|worksheets/sheet\d+|comments\d*|threadedComments/[^/]+|persons/[^/]+|charts/[^/]+)\.xml"
    r"|ppt/(?:slides/slide\d+|notesSlides/notesSlide\d+|comments/[^/]+|commentAuthors|authors|charts/[^/]+)\.xml"
    r"|docProps/(?:core|app|custom)\.xml"
    r"|Contents/(?:section\d+|content)\.(?:xml|hpf)"
    r"|content\.xml|meta\.xml|styles\.xml"
    r")$")
_EMBEDDED = re.compile(r"^(?:word|xl|ppt)/embeddings/[^/]+\.(?:docx|xlsx|pptx)$", re.I)

PARA = {"p", "h", "si", "row", "comment", "cm", "threadedComment"}
TEXT = {"t", "instrText", "f", "author", "text"}
DELETED = {"delText"}
# Attributes that name people: tracked-change and comment authors, user ids.
PERSON_ATTRS = {"author", "initials", "userId", "creator", "displayName"}


# Metadata keys whose value is a person. PDF `/Creator` is the application, so
# only lower-case `creator` (Dublin Core, OOXML/ODF/HWPX) counts.
PERSON_KEYS = {"creator", "lastModifiedBy", "Author", "author", "initial-creator", "Manager",
               "manager", "LastSavedBy"}
GENERIC_AUTHORS = {"user", "admin", "administrator", "author", "unknown", "microsoft office user",
                   "microsoft office 사용자", "python-docx", "openpyxl", "python-pptx", "windows 사용자"}


def people(where: str, text: str) -> list[tuple[int, int, str]]:
    """(line, column, name) for every person named in an authors/properties segment."""
    if not (where.endswith(("[authors]", "[properties]", "[annotations]")) or where == "metadata"):
        return []
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        key, sep, value = line.partition(": ")
        name = value.strip()
        if sep and key in PERSON_KEYS and name and name.lower() not in GENERIC_AUTHORS:
            out.append((i, len(key) + 2, name))
    return out


@dataclass
class Extraction:
    segments: list[tuple[str, str]] = field(default_factory=list)   # (location, text)
    unscanned: str | None = None                                   # reason, if unreadable


def kind(path: Path) -> str | None:
    s = path.suffix.lower()
    return s if s in CONTAINERS else None


def extract(path: Path, ocr: bool = False) -> Extraction:
    s = path.suffix.lower()
    if path.name.startswith("~$"):
        return Extraction(unscanned="Office lock file (it stores the editor's user name); delete it")
    try:
        if path.stat().st_size > MAX_CONTAINER_BYTES:
            return Extraction(unscanned=f"larger than {MAX_CONTAINER_BYTES // 2**20} MB")
        if s in OOXML | ODF | HWPX:
            return _zip_document(path.read_bytes())
        if s in PDF:
            return _pdf(path)
        if s in IMAGES:
            return _image(path) if ocr else Extraction(unscanned="image (use --ocr)")
        return Extraction(unscanned=f"no reader for {s} files")
    except (zipfile.BadZipFile, ET.ParseError, OSError, ValueError) as e:
        return Extraction(unscanned=f"unreadable: {type(e).__name__}: {e}")


# -- Office Open XML / OpenDocument / HWPX -------------------------------------
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _zip_document(data: bytes, depth: int = 0) -> Extraction:
    ex = Extraction()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        odf = "mimetype" in z.namelist() and z.read("mimetype").startswith(b"application/vnd.oasis")
        for info in z.infolist():
            name = info.filename
            if info.file_size > MAX_PART_BYTES:
                ex.unscanned = f"part {name} larger than {MAX_PART_BYTES // 2**20} MB"
                continue
            if depth == 0 and _EMBEDDED.match(name):
                inner = _zip_document(z.read(name), depth + 1)
                ex.segments += [(f"{name}!{loc}", t) for loc, t in inner.segments]
                ex.unscanned = ex.unscanned or inner.unscanned
                continue
            if not _PART.match(name) or (name == "styles.xml" and not odf):
                continue
            root = ET.fromstring(z.read(name))
            kept, deleted, people = _paragraphs(root, odf)
            if kept:
                ex.segments.append((name, "\n".join(kept)))
            if deleted:
                ex.segments.append((f"{name} [tracked deletion]", "\n".join(deleted)))
            if people:
                ex.segments.append((f"{name} [authors]",
                                    "\n".join(f"author: {p}" for p in sorted(people))))
            if name.endswith(("core.xml", "app.xml", "custom.xml", "meta.xml", "content.hpf")):
                props = [f"{e.get('name') or _local(e.tag)}: {e.text.strip()}" for e in root.iter()
                         if e.text and e.text.strip() and not len(e)]
                if props:
                    ex.segments.append((f"{name} [properties]", "\n".join(props)))
    return ex


def _paragraphs(root: ET.Element, odf: bool) -> tuple[list[str], list[str], set[str]]:
    kept: list[str] = []
    deleted: list[str] = []
    people: set[str] = set()
    for el in root.iter():
        for k, v in el.attrib.items():
            if _local(k) in PERSON_ATTRS and v.strip():
                people.add(v.strip())
        tag = _local(el.tag)
        if tag == "cmAuthor" and el.get("name"):
            people.add(el.get("name"))
        elif tag == "author" and el.text and el.text.strip():      # xlsx <authors><author>
            people.add(el.text.strip())

    def collect(el: ET.Element, buf: list[str], dbuf: list[str]) -> None:
        for child in el:
            t = _local(child.tag)
            if t in PARA:
                paragraph(child)
            elif odf:
                continue
            elif t in DELETED:
                dbuf.append(child.text or "")
            elif t in TEXT:
                buf.append(child.text or "")
                collect(child, buf, dbuf)
            elif t == "v" and child.text and el.get("t") != "s":   # xlsx value, not a string index
                buf.append(child.text)
            elif t == "tab":
                buf.append("\t")
            elif t in ("br", "cr"):
                buf.append(" ")
            else:
                collect(child, buf, dbuf)
            if t == "c":                                          # xlsx cell boundary
                buf.append("\t")

    def paragraph(el: ET.Element) -> None:
        if odf:
            line = "".join(el.itertext())
            if line.strip():
                kept.append(line)
            return
        buf: list[str] = []
        dbuf: list[str] = []
        collect(el, buf, dbuf)
        line, dline = "".join(buf).strip("\t "), "".join(dbuf)
        if line.strip():
            kept.append(line)
        if dline.strip():
            deleted.append(dline)

    def walk(el: ET.Element) -> None:
        for child in el:
            if _local(child.tag) in PARA:
                paragraph(child)
            else:
                walk(child)

    walk(root)
    return kept, deleted, people


# -- PDF -------------------------------------------------------------------------
def _pdf(path: Path) -> Extraction:
    try:
        import pypdf
    except ImportError:
        return Extraction(unscanned="PDF reader not installed (pip install 'leakgate[pdf]')")
    import logging

    class _Collect(logging.Handler):
        def __init__(self):
            super().__init__(logging.WARNING)
            self.messages: list[str] = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    log, grab = logging.getLogger("pypdf"), _Collect()
    log.addHandler(grab)
    log.propagate, saved = False, log.propagate
    try:
        ex = _pdf_read(pypdf, path)
    finally:
        log.removeHandler(grab)
        log.propagate = saved
    # pypdf warns and returns what it could when a CMap/encoding is unsupported
    # (Korean `/UniKS-UTF16-H` seen in real files): that page text is incomplete.
    lost = sorted({m for m in grab.messages if "not implemented" in m or "encoding" in m.lower()})
    if lost and not ex.unscanned:
        ex.unscanned = "PDF text only partly decoded: " + "; ".join(lost)[:120]
    return ex


def _pdf_read(pypdf, path: Path) -> Extraction:
    reader = pypdf.PdfReader(str(path))
    if reader.is_encrypted and not reader.decrypt(""):
        return Extraction(unscanned="encrypted PDF")
    ex = Extraction()
    chars = 0
    for i, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        chars += len(text.strip())
        if text.strip():
            ex.segments.append((f"page {i}", text))
        notes = []
        for a in page.get("/Annots") or []:
            a = a.get_object()
            for key in ("/T", "/Contents"):
                if a.get(key):
                    notes.append(f"{'author' if key == '/T' else 'comment'}: {a.get(key)}")
        if notes:
            ex.segments.append((f"page {i} [annotations]", "\n".join(notes)))
    meta = reader.metadata or {}
    props = [f"{k.lstrip('/')}: {v}" for k, v in meta.items() if v]
    if props:
        ex.segments.append(("metadata", "\n".join(props)))
    if reader.pages and chars == 0:
        ex.unscanned = "PDF has no text layer (scanned image); OCR it first"
    return ex


# -- images ------------------------------------------------------------------------
def _image(path: Path) -> Extraction:
    exe = shutil.which("tesseract")
    if not exe:
        return Extraction(unscanned="OCR requested but `tesseract` is not on PATH")
    r = subprocess.run([exe, str(path), "stdout", "-l", "kor+eng"], capture_output=True,
                       encoding="utf-8", errors="replace", timeout=120)
    if r.returncode != 0:
        return Extraction(unscanned=f"tesseract failed: {r.stderr.strip()[:120]}")
    return Extraction(segments=[("ocr", r.stdout)] if r.stdout.strip() else [])

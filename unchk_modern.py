#!/usr/bin/env python3
"""Modern CHK fragment recognizer inspired by UnCHK and FileCHK.

The program never modifies source CHK files. It copies matching fragments to
an output directory with an inferred extension.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


ScanMode = str


@dataclass(frozen=True)
class Match:
    offset: int
    extension: str
    kind: str
    confidence: str
    reason: str


@dataclass(frozen=True)
class Signature:
    kind: str
    extension: str
    header: bytes
    contains: bytes = b""
    confidence: str = "normal"
    source: str = "unchk"
    deep: bool = True

    def matches(self, data: bytes, offset: int) -> bool:
        if offset and not self.deep:
            return False
        if not self.header:
            return False
        if not data.startswith(self.header, offset):
            return False
        if not self.contains:
            return True
        return data.find(self.contains, offset) >= 0


Detector = Callable[[bytes, int], Iterable[Match]]


def hx(value: str) -> bytes:
    """Decode legacy hex strings, ignoring spaces and non-hex text."""
    clean = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
    if len(clean) % 2:
        clean = clean[:-1]
    return bytes.fromhex(clean)


def b(text: str) -> bytes:
    return text.encode("latin-1")


def default_signatures() -> list[Signature]:
    # Names preserve legacy variants, while extensions are normalized for output.
    return [
        Signature("3ds-mm", "3ds", b"MM", source="filechk", deep=False),
        Signature("tif-ii", "tif", b"II", hx("2A00")),
        Signature("tif-mm", "tif", b"MM", hx("002A")),
        Signature("exe", "exe", b"MZ", b"This program"),
        Signature("dll", "dll", b"MZ", b"This program"),
        Signature("ocx", "ocx", b"MZ", b"DllRegisterServer"),
        Signature("bmp", "bmp", b"BM", source="filechk", deep=False),
        Signature("bmp-4", "bmp", b"BM", hx("000000003600000028000000")),
        Signature("bmp-8", "bmp", b"BM", hx("000000003604000028000000")),
        Signature("bmp-24", "bmp", b"BM", hx("000000007600000028000000")),
        Signature("swf", "swf", b"FWS", source="filechk", deep=False),
        Signature("ai", "ai", b"%!PS", source="filechk", deep=False),
        Signature("gif", "gif", b"GIF8", source="filechk", deep=False),
        Signature("gif87", "gif", b"GIF87"),
        Signature("gif89", "gif", b"GIF89"),
        Signature("pst", "pst", b"!BDN", source="filechk", deep=False),
        Signature("cab", "cab", b"MSCF"),
        Signature("rar", "rar", b"Rar!"),
        Signature("chm", "chm", b"ITSF", b"ITSP"),
        Signature("mid", "mid", b"MThd", b"MTrk"),
        Signature("pdf", "pdf", b"%PDF-"),
        Signature("zip", "zip", hx("504B0304")),
        Signature("hlp", "hlp", b"?_" + hx("0300"), source="filechk", deep=False),
        Signature("dwg", "dwg", b"AC1015", source="filechk", deep=False),
        Signature("html-doctype-upper", "html", b"<!DOCTYPE ", b"<HTML"),
        Signature("html-doctype-lower", "htm", b"<!DOCTYPE ", b"<html"),
        Signature("html-upper", "html", b"<HTML"),
        Signature("html-lower", "htm", b"<html"),
        Signature("jpg-jfif", "jpg", hx("FFD8FFE0"), b"JFIF"),
        Signature("jpg-exif", "jpg", hx("FFD8FFE1"), b"Exif"),
        Signature("png", "png", hx("89504E470D0A1A")),
        Signature("rtf", "rtf", b"{\\rtf", b"{\\fonttbl"),
        Signature("wpg", "wpg", b"WPC"),
        Signature("wpg-5", "wpg", hx("FF") + b"WPC"),
        Signature("wri", "wri", b"1" + hx("BE"), hx("2E0D0A")),
        Signature("clp", "clp", hx("50C30100")),
        Signature("psp", "psp", b"Paint Shop Pro Image File"),
        Signature("eps", "eps", hx("C5D0D3")),
        Signature("fpx", "fpx", hx("D0CF"), hx("49006D00610067006500000043006F006E00740065006E00740073")),
        Signature("doc-legacy", "doc", hx("D0CF"), b"Microsoft Word"),
        Signature("ppt-legacy", "ppt", hx("D0CF"), b"Microsoft PowerPoint"),
        Signature("xls-legacy", "xls", hx("D0CF"), b"Microsoft Excel"),
        Signature("avi-legacy", "avi", b"RIFF", b"AVI"),
        Signature("wav-legacy", "wav", b"RIFF", b"WAVE"),
        Signature("mp3-id3", "mp3", b"ID3" + hx("02")),
    ]


def load_extra_signatures(path: Path | None) -> list[Signature]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    signatures: list[Signature] = []
    for item in raw:
        signatures.append(
            Signature(
                kind=item["kind"],
                extension=item.get("extension", item["kind"]).lower().lstrip("."),
                header=hx(item["header_hex"]),
                contains=hx(item.get("contains_hex", "")),
                confidence=item.get("confidence", "custom"),
                source="custom",
            )
        )
    return signatures


def special_detectors() -> list[Detector]:
    return [
        detect_riff,
        detect_office,
        detect_psd,
        detect_textual_code,
        detect_jpeg,
        detect_quicktime,
        detect_asf,
        detect_lnk,
        detect_url,
        detect_ttf,
        detect_mdb,
        detect_mp3_frame,
    ]


def detect_riff(data: bytes, offset: int) -> Iterable[Match]:
    if not data.startswith(b"RIFF", offset) or offset + 12 > len(data):
        return []
    form = data[offset + 8 : offset + 12]
    mapping = {
        b"RMID": ("rmi", "RIFF/RMID"),
        b"WAVE": ("wav", "RIFF/WAVE"),
        b"AVI ": ("avi", "RIFF/AVI"),
        b"CDR8": ("cdr", "RIFF/CDR8"),
        b"CDR9": ("cdr", "RIFF/CDR9"),
    }
    if form in mapping:
        ext, reason = mapping[form]
        return [Match(offset, ext, ext, "high", reason)]
    return []


def detect_office(data: bytes, offset: int) -> Iterable[Match]:
    if not data.startswith(hx("D0CF11E0"), offset):
        return []
    probe = data[offset : min(len(data), offset + 16384)].lower()
    if b"word" in probe or b"microsoft word" in probe:
        return [Match(offset, "doc", "office-doc", "high", "OLE compound document contains Word marker")]
    if b"excel" in probe or b"microsoft excel" in probe:
        return [Match(offset, "xls", "office-xls", "high", "OLE compound document contains Excel marker")]
    if b"powerpoint" in probe or b"microsoft powerpoint" in probe:
        return [Match(offset, "ppt", "office-ppt", "high", "OLE compound document contains PowerPoint marker")]
    return [Match(offset, "ole", "office-ole", "low", "OLE compound document")]


def detect_jpeg(data: bytes, offset: int) -> Iterable[Match]:
    if not data.startswith(hx("FFD8FF"), offset):
        return []
    probe = data[offset : min(len(data), offset + 64)]
    if b"JFIF" in probe:
        return [Match(offset, "jpg", "jpg-jfif", "high", "JPEG/JFIF marker")]
    if b"Exif" in probe:
        return [Match(offset, "jpg", "jpg-exif", "high", "JPEG/Exif marker")]
    return [Match(offset, "jpg", "jpg-generic", "normal", "JPEG SOI marker")]


def detect_psd(data: bytes, offset: int) -> Iterable[Match]:
    if offset + 26 > len(data) or not data.startswith(b"8BPS", offset):
        return []
    header = data[offset : offset + 26]
    version = int.from_bytes(header[4:6], "big")
    reserved = header[6:12]
    channels = int.from_bytes(header[12:14], "big")
    height = int.from_bytes(header[14:18], "big")
    width = int.from_bytes(header[18:22], "big")
    depth = int.from_bytes(header[22:24], "big")
    color_mode = int.from_bytes(header[24:26], "big")
    if (
        version in (1, 2)
        and reserved == b"\0" * 6
        and 1 <= channels <= 56
        and 1 <= height <= 300000
        and 1 <= width <= 300000
        and depth in (1, 8, 16, 32)
        and 0 <= color_mode <= 9
    ):
        return [Match(offset, "psd", "psd", "high", "Photoshop header")]
    return []


def detect_textual_code(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0 or not data:
        return []
    sample = data[: min(len(data), 65536)]
    allowed = set(range(32, 127)) | {9, 10, 13}
    ascii_count = sum(1 for value in sample if value in allowed)
    if ascii_count == 0 or len(sample) / ascii_count >= 1.15:
        return []

    text = sample.decode("utf-8", errors="ignore").lstrip("\ufeff \t\r\n")
    lower = text.lower()
    if not text:
        return []
    if lower.startswith("<!doctype html") or lower.startswith("<html"):
        return [Match(0, "html", "html-text", "normal", "HTML text")]
    if lower.startswith("<?xml"):
        return [Match(0, "xml", "xml-text", "normal", "XML text")]
    if lower.startswith("<svg") or "<svg" in lower[:256]:
        return [Match(0, "svg", "svg-text", "normal", "SVG text")]
    if looks_like_json(text):
        return [Match(0, "json", "json-text", "normal", "JSON text")]
    if looks_like_css(text):
        return [Match(0, "css", "css-text", "low", "CSS-like text")]
    if looks_like_javascript(text):
        return [Match(0, "js", "js-text", "low", "JavaScript-like text")]
    return []


def looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if not ((stripped.startswith("{") and "}" in stripped) or (stripped.startswith("[") and "]" in stripped)):
        return False
    return bool(re.search(r'"[^"]+"\s*:', stripped[:4096]))


def looks_like_css(text: str) -> bool:
    head = text[:4096]
    if re.search(r"(@media|@font-face|body\s*\{|html\s*\{|#[A-Za-z0-9_-]+\s*\{|\.[A-Za-z0-9_-]+\s*\{)", head):
        return True
    return bool(re.search(r"[A-Za-z-]+\s*:\s*[^;{}]+;", head) and "{" in head and "}" in head)


def looks_like_javascript(text: str) -> bool:
    head = text[:8192]
    markers = [
        r"\bfunction\b",
        r"\bconst\b",
        r"\blet\b",
        r"\bvar\b",
        r"=>",
        r"\bimport\s+",
        r"\bexport\s+",
        r"document\.",
        r"window\.",
        r"console\.",
        r"require\(",
    ]
    return sum(1 for marker in markers if re.search(marker, head)) >= 2


def detect_quicktime(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    if offset + 12 > len(data):
        return []
    if data[offset + 4 : offset + 8] == b"moov":
        return [Match(offset, "mov", "quicktime-moov", "normal", "QuickTime moov atom")]
    if data[offset + 4 : offset + 8] == b"ftyp":
        brand = data[offset + 8 : offset + 12].lower()
        ext = "mov" if brand in {b"qt  ", b"moov"} else "mp4"
        return [Match(offset, ext, "iso-bmff", "normal", "ISO media ftyp atom")]
    return []


def detect_asf(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    asf = hx("3026B2758E66CF11A6D900AA0062CE6C")
    if data.startswith(asf, offset):
        return [Match(offset, "asf", "asf", "high", "ASF GUID")]
    return []


def detect_lnk(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    lnk = hx("4C0000000114020000000000C0000000")
    if data.startswith(lnk, offset):
        return [Match(offset, "lnk", "lnk", "high", "Windows shortcut header")]
    return []


def detect_url(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    if data.startswith(b"[InternetShortcu", offset):
        return [Match(offset, "url", "url", "high", "Internet shortcut header")]
    return []


def detect_ttf(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    if offset + 16 <= len(data) and data[offset + 12 : offset + 16] == b"DSIG":
        return [Match(offset, "ttf", "ttf", "normal", "TrueType DSIG marker")]
    return []


def detect_mdb(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    if offset + 16 <= len(data) and data[offset + 4 : offset + 16] == b"Standard Jet":
        return [Match(offset, "mdb", "mdb", "high", "Microsoft Jet database marker")]
    return []


def detect_mp3_frame(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0:
        return []
    if data.startswith(hx("FFFBD0040000"), offset):
        return [Match(offset, "mp3", "mp3-frame", "normal", "MP3 frame header used by FileCHK")]
    return []


def detect_text(data: bytes, offset: int) -> Iterable[Match]:
    if offset != 0 or len(data) >= 0x100000 or not data:
        return []
    allowed = set(range(32, 127)) | {9, 10, 13}
    ascii_count = sum(1 for value in data if value in allowed)
    if ascii_count and len(data) / ascii_count < 1.25:
        return [Match(0, "txt", "txt", "low", "mostly printable ASCII")]
    return []


def offsets_for(mode: ScanMode, length: int) -> range:
    if mode == "whole":
        return range(0, min(length, 1))
    if mode == "embedded":
        return range(0, length)
    if mode == "floppy":
        return range(0, length, 128)
    if mode == "harddisk":
        return range(0, length, 512)
    raise ValueError(f"Unknown scan mode: {mode}")


def build_signature_index(signatures: list[Signature]) -> dict[int, list[Signature]]:
    index: dict[int, list[Signature]] = {}
    for sig in signatures:
        if sig.header:
            index.setdefault(sig.header[0], []).append(sig)
    return index


def find_matches(data: bytes, mode: ScanMode, signatures: list[Signature]) -> list[Match]:
    detectors = special_detectors()
    index = build_signature_index(signatures)
    found: list[Match] = []
    seen: set[tuple[int, str]] = set()

    for offset in offsets_for(mode, len(data)):
        first = data[offset] if offset < len(data) else None
        for detector in detectors:
            for match in detector(data, offset):
                key = (match.offset, match.extension)
                if key not in seen:
                    found.append(match)
                    seen.add(key)

        for sig in index.get(first, []):
            if sig.matches(data, offset):
                match = Match(offset, sig.extension, sig.kind, sig.confidence, f"{sig.source} signature")
                key = (match.offset, match.extension)
                if key not in seen:
                    found.append(match)
                    seen.add(key)

    if not found and mode == "whole":
        found.extend(detect_text(data, 0))

    return found


def source_files(source: Path, filechk_only: bool) -> list[Path]:
    pattern = "FILE????.CHK" if filechk_only else "*.CHK"
    files = sorted(source.glob(pattern))
    if not files and not filechk_only:
        files = sorted(source.glob("*.chk"))
    return [path for path in files if path.is_file()]


def unique_output_path(out_dir: Path, source: Path, match: Match) -> Path:
    stem = source.stem
    if match.offset:
        stem = f"{stem}@{match.offset:08X}"
    candidate = out_dir / f"{stem}.{match.extension}"
    counter = 1
    while candidate.exists():
        candidate = out_dir / f"{stem}-{counter}.{match.extension}"
        counter += 1
    return candidate


def write_match(out_dir: Path, source: Path, data: bytes, match: Match, dry_run: bool) -> Path:
    target = unique_output_path(out_dir, source, match)
    if not dry_run:
        target.write_bytes(data[match.offset :])
    return target


def scan_command(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    out_dir = Path(args.out).resolve()
    if not source.exists() or not source.is_dir():
        print(f"Source directory not found: {source}", file=sys.stderr)
        return 2
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    signatures = default_signatures() + load_extra_signatures(Path(args.signatures).resolve() if args.signatures else None)
    files = source_files(source, args.filechk_names)
    if args.max_files:
        files = files[: args.max_files]

    log_path = Path(args.log).resolve() if args.log else out_dir / "unchk-modern.log"
    rows: list[dict[str, str]] = []
    recovered = 0
    errors = 0

    print(f"Scanning {len(files)} CHK file(s) in {source}")
    print(f"Mode: {args.mode}; output: {out_dir}; dry-run: {args.dry_run}")

    for index, path in enumerate(files, start=1):
        try:
            data = path.read_bytes()
            matches = find_matches(data, args.mode, signatures)
        except OSError as exc:
            errors += 1
            rows.append(
                {
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "source": str(path),
                    "status": "error",
                    "match": "",
                    "offset": "",
                    "output": "",
                    "reason": str(exc),
                }
            )
            continue

        if not matches:
            rows.append(
                {
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "source": str(path),
                    "status": "unmatched",
                    "match": "",
                    "offset": "",
                    "output": "",
                    "reason": "",
                }
            )
        else:
            for match in matches:
                tail_len = len(data) - match.offset
                max_copy_bytes = args.max_copy_mb * 1024 * 1024 if args.max_copy_mb else 0
                skipped_large = bool(max_copy_bytes and tail_len > max_copy_bytes)
                target = unique_output_path(out_dir, path, match)
                if not skipped_large:
                    target = write_match(out_dir, path, data, match, args.dry_run)
                    recovered += 1
                rows.append(
                    {
                        "time": datetime.now().isoformat(timespec="seconds"),
                        "source": str(path),
                        "status": "skipped-large" if skipped_large else ("dry-run" if args.dry_run else "recovered"),
                        "match": f"{match.kind}.{match.extension}",
                        "offset": str(match.offset),
                        "output": str(target),
                        "reason": f"{match.reason}; tail={tail_len} bytes",
                    }
                )

        if index == len(files) or index % args.progress_every == 0:
            print(f"{index}/{len(files)} files checked; {recovered} recovered candidate(s)")

    if args.write_log and not args.dry_run:
        write_log(log_path, rows)
        print(f"Log written: {log_path}")
    elif args.write_log and args.dry_run:
        write_log(log_path, rows)
        print(f"Dry-run log written: {log_path}")

    print(f"Done. Candidates: {recovered}; errors: {errors}; unmatched: {sum(1 for row in rows if row['status'] == 'unmatched')}")
    return 1 if errors else 0


def carve_command(args: argparse.Namespace) -> int:
    source = Path(args.source).resolve()
    out_dir = Path(args.out).resolve()
    if not source.exists() or not source.is_dir():
        print(f"Source directory not found: {source}", file=sys.stderr)
        return 2
    header = hx(args.header_hex)
    contains = hx(args.contains_hex or "")
    if not header:
        print("Header is empty after hex decoding.", file=sys.stderr)
        return 2
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    files = source_files(source, args.filechk_names)
    if args.max_files:
        files = files[: args.max_files]

    log_path = Path(args.log).resolve() if args.log else out_dir / f"carve-{args.extension.lower().lstrip('.')}.log"
    rows: list[dict[str, str]] = []
    recovered = 0
    errors = 0
    max_copy_bytes = args.max_copy_mb * 1024 * 1024 if args.max_copy_mb else 0

    print(f"Carving {len(files)} CHK file(s) in {source}")
    print(f"Signature: {header.hex().upper()} -> .{args.extension}; output: {out_dir}; dry-run: {args.dry_run}")

    for index, path in enumerate(files, start=1):
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors += 1
            rows.append(
                {
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "source": str(path),
                    "status": "error",
                    "match": "",
                    "offset": "",
                    "output": "",
                    "reason": str(exc),
                }
            )
            continue

        offset = data.find(header)
        while offset >= 0:
            if not contains or data.find(contains, offset) >= 0:
                match = Match(offset, args.extension.lower().lstrip("."), f"carve-{args.extension}", "targeted", "targeted byte signature")
                tail_len = len(data) - offset
                skipped_large = bool(max_copy_bytes and tail_len > max_copy_bytes)
                target = unique_output_path(out_dir, path, match)
                if not skipped_large:
                    target = write_match(out_dir, path, data, match, args.dry_run)
                    recovered += 1
                rows.append(
                    {
                        "time": datetime.now().isoformat(timespec="seconds"),
                        "source": str(path),
                        "status": "skipped-large" if skipped_large else ("dry-run" if args.dry_run else "recovered"),
                        "match": f"carve.{match.extension}",
                        "offset": str(offset),
                        "output": str(target),
                        "reason": f"targeted byte signature; tail={tail_len} bytes",
                    }
                )
            offset = data.find(header, offset + 1)

        if index == len(files) or index % args.progress_every == 0:
            print(f"{index}/{len(files)} files checked; {recovered} carved candidate(s)")

    if args.write_log or rows:
        write_log(log_path, rows)
        print(f"Log written: {log_path}")

    print(f"Done. Candidates: {recovered}; errors: {errors}; matches logged: {len(rows)}")
    return 1 if errors else 0


def write_log(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["time", "source", "status", "match", "offset", "output", "reason"], delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def learn_command(args: argparse.Namespace) -> int:
    sample = Path(args.file).resolve()
    if not sample.is_file():
        print(f"File not found: {sample}", file=sys.stderr)
        return 2
    data = sample.read_bytes()
    header_len = min(args.bytes, len(data))
    ext = sample.suffix.lower().lstrip(".")
    item = {
        "kind": ext or sample.stem.lower(),
        "extension": ext or "bin",
        "header_hex": data[:header_len].hex().upper(),
        "contains_hex": "",
        "confidence": "custom",
    }
    print(json.dumps([item], indent=2))
    return 0


def list_types_command(args: argparse.Namespace) -> int:
    signatures = default_signatures() + load_extra_signatures(Path(args.signatures).resolve() if args.signatures else None)
    for sig in signatures:
        contains = f" contains={sig.contains.hex().upper()}" if sig.contains else ""
        print(f"{sig.kind:24s} -> .{sig.extension:5s} header={sig.header.hex().upper()}{contains}")
    print("special detectors: riff, office, jpeg, quicktime, asf, lnk, url, ttf, mdb, mp3-frame, txt")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recover likely file fragments from CHK files without modifying originals.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a directory containing CHK files")
    scan.add_argument("source", help="Directory containing CHK files, for example C:\\FOUND.000")
    scan.add_argument("--out", required=True, help="Output directory for recovered copies")
    scan.add_argument("--mode", choices=["whole", "harddisk", "floppy", "embedded"], default="harddisk")
    scan.add_argument("--filechk-names", action="store_true", help="Only scan FILE????.CHK names, like FileCHK")
    scan.add_argument("--signatures", help="Optional JSON file with extra signatures")
    scan.add_argument("--write-log", action="store_true", help="Write a tab-separated recovery log")
    scan.add_argument("--log", help="Log path; defaults to output\\unchk-modern.log")
    scan.add_argument("--dry-run", action="store_true", help="Detect and log without writing recovered files")
    scan.add_argument("--max-copy-mb", type=int, default=0, help="Skip writing candidates larger than this many MiB; 0 means no limit")
    scan.add_argument("--max-files", type=int, default=0, help="Limit number of files for a trial run")
    scan.add_argument("--progress-every", type=int, default=100, help="Progress interval")
    scan.set_defaults(func=scan_command)

    carve = sub.add_parser("carve", help="Targeted byte-signature carving, useful for one suspected format")
    carve.add_argument("source", help="Directory containing CHK files")
    carve.add_argument("--out", required=True, help="Output directory for carved copies")
    carve.add_argument("--extension", required=True, help="Extension to use for carved candidates, for example psd")
    carve.add_argument("--header-hex", required=True, help="Hex signature to search anywhere in each CHK file")
    carve.add_argument("--contains-hex", help="Optional hex bytes that must appear after the header")
    carve.add_argument("--filechk-names", action="store_true", help="Only scan FILE????.CHK names")
    carve.add_argument("--write-log", action="store_true", help="Write a tab-separated carve log")
    carve.add_argument("--log", help="Log path")
    carve.add_argument("--dry-run", action="store_true", help="Detect and log without writing carved files")
    carve.add_argument("--max-copy-mb", type=int, default=0, help="Skip writing candidates larger than this many MiB; 0 means no limit")
    carve.add_argument("--max-files", type=int, default=0, help="Limit number of files for a trial run")
    carve.add_argument("--progress-every", type=int, default=100, help="Progress interval")
    carve.set_defaults(func=carve_command)

    learn = sub.add_parser("learn", help="Generate a custom signature entry from a known-good file")
    learn.add_argument("file")
    learn.add_argument("--bytes", type=int, default=8, help="Number of leading bytes to use")
    learn.set_defaults(func=learn_command)

    list_types = sub.add_parser("list-types", help="List built-in signatures")
    list_types.add_argument("--signatures", help="Optional JSON file with extra signatures")
    list_types.set_defaults(func=list_types_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

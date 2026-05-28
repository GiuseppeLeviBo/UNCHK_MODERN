# UnCHK Modern

UnCHK Modern is a small, dependency-free command line tool for inspecting and
recovering likely file fragments from Windows `CHK` files.

It was inspired by the legacy Visual Basic utilities **UnCHK** by Eric Phelps
and **FileCHK** by Martin Kratz. The goal is not to perform low-level disk
undelete operations. Instead, this tool works on files that already exist in a
directory such as `FOUND.000`, usually created by `CHKDSK`, and tries to identify
what each `FILE0000.CHK` fragment may contain.

The program never modifies the source `CHK` files. It only writes recovered
copies to an output directory.

## Current Status

This is an early rewrite focused on safety, testability, and transparent
logging. It combines ideas from both legacy tools:

- configurable file signatures, similar to UnCHK;
- whole-file and internal-boundary scanning modes;
- stronger built-in detectors for formats where a simple magic byte check is
  too weak;
- text/code classification for common web fragments;
- tab-separated logs that record the source file, detected type, offset, output
  path, and reason for the match.

## Requirements

- Python 3.10 or newer.
- No required third-party dependencies.

The project intentionally avoids mandatory dependencies so it can run on a
plain Windows machine. A future optional integration with `python-magic` /
`libmagic` may be useful as a second opinion, but the core recovery logic is
kept internal and portable.

## Quick Start

Run the tests:

```powershell
python -m unittest -v test_unchk_modern.py
```

Scan a `FOUND.000` directory conservatively:

```powershell
python unchk_modern.py scan D:\RECUPERO\FOUND.000 --out D:\RECUPERO\recovered_whole --mode whole --write-log
```

Preview a deeper scan without writing recovered files:

```powershell
python unchk_modern.py scan D:\RECUPERO\FOUND.000 --out D:\RECUPERO\preview_floppy --mode floppy --write-log --dry-run
```

List built-in signatures:

```powershell
python unchk_modern.py list-types
```

Launch the desktop GUI:

```powershell
python unchk_gui.py
```

## Scan Modes

The scan modes preserve the terminology used by the original UnCHK utility:

| Mode | What It Checks | Typical Use |
| --- | --- | --- |
| `whole` | Offset `0` only | Safest first pass. Finds fragments that begin with a recognizable file header. |
| `harddisk` | Every `512` bytes | Looks for embedded starts on sector-like boundaries. More false positives. |
| `floppy` | Every `128` bytes | Denser boundary scan. Can help with removable media, but produces more noise. |
| `embedded` | Every byte | Last resort. Very slow and very noisy on large files. |

Start with `whole`. Then inspect the log before trying deeper modes.

## Important Limitations

UnCHK Modern identifies likely file starts. It does not reconstruct a fragmented
file by automatically joining multiple `CHK` files.

If an original file was split across several fragments, the tool may recover the
first fragment, or a later embedded fragment, but manual analysis may still be
needed. This is especially true for large videos, PSD/PSB files, archives, and
Office documents.

Some formats contain misleading internal markers. For example:

- JPEG files exported by Photoshop often contain `Photoshop` and `8BIM` markers,
  but they are still JPEG files, not PSD files.
- A raw `8BPS` byte sequence is not enough to prove a Photoshop PSD. The built-in
  PSD detector validates the surrounding header fields.
- Very short signatures such as `MM` or `BM` are only useful in limited contexts
  and can create false positives inside large binary files.

## Desktop GUI

The repository includes a Tkinter desktop interface:

```powershell
python unchk_gui.py
```

The GUI exposes the common scan settings:

- source directory;
- output directory;
- optional custom signatures JSON file;
- scan mode;
- `FILE????.CHK` filtering;
- dry-run mode;
- log writing;
- maximum copy size guard;
- maximum file limit for trial runs.

The scan runs on a background thread, so the window remains responsive while
large `FOUND.000` directories are being inspected.

### Build a Windows EXE

Install PyInstaller:

```powershell
python -m pip install pyinstaller
```

Build the GUI executable:

```powershell
python -m PyInstaller unchk_gui.spec
```

The resulting executable is written under:

```text
dist\UnCHK Modern\UnCHK Modern.exe
```

The command line tool can also be packaged separately if desired, but the GUI
build is the most convenient distribution for non-technical users.

## Command Reference

### `scan`

```powershell
python unchk_modern.py scan SOURCE --out OUTPUT [options]
```

Options:

- `--mode whole|harddisk|floppy|embedded`
- `--filechk-names` only scan names matching `FILE????.CHK`
- `--signatures PATH` load extra JSON signatures
- `--write-log` write a tab-separated log
- `--log PATH` choose a custom log path
- `--dry-run` detect and log without writing recovered files
- `--max-copy-mb N` skip writing candidates larger than `N` MiB
- `--max-files N` limit input files for a trial run
- `--progress-every N` progress interval

Example with a size guard:

```powershell
python unchk_modern.py scan D:\RECUPERO\FOUND.000 --out D:\RECUPERO\recovered_harddisk --mode harddisk --write-log --max-copy-mb 256
```

Large candidates skipped by `--max-copy-mb` are still written to the log as
`skipped-large`, so you can review them later.

### `carve`

`carve` performs a targeted byte-signature search. It is useful when you strongly
suspect one specific format and want to avoid a noisy full embedded scan.

```powershell
python unchk_modern.py carve D:\RECUPERO\FOUND.000 --out D:\RECUPERO\psd_candidates --extension psd --header-hex 38425053 --write-log --dry-run
```

This example searches for `8BPS`, the PSD/PSB header. A raw carved result still
needs validation; the normal `scan` command already includes a stronger PSD
header detector.

### `learn`

Generate a JSON signature entry from a known-good sample file:

```powershell
python unchk_modern.py learn example.foo --bytes 8
```

The output is a JSON snippet you can copy into a custom signatures file.

### `list-types`

Show built-in signatures, optionally including a custom JSON file:

```powershell
python unchk_modern.py list-types --signatures custom_signatures.example.json
```

## Custom Signatures

Extra signatures are loaded from a JSON file containing a list of objects:

```json
[
  {
    "kind": "sqlite",
    "extension": "sqlite",
    "header_hex": "53514C69746520666F726D6174203300",
    "contains_hex": "",
    "confidence": "high"
  }
]
```

Fields:

- `kind`: internal name shown in logs.
- `extension`: output extension without the leading dot.
- `header_hex`: required byte sequence that must appear at the tested offset.
- `contains_hex`: optional byte sequence that must appear after the header.
- `confidence`: free-form label such as `high`, `normal`, `low`, or `custom`.

See [custom_signatures.example.json](custom_signatures.example.json) for a
larger example file.

## Built-In Detection Highlights

The current built-in rules cover common legacy and modern file types, including:

- images: JPEG, PNG, GIF, BMP, TIFF, PSD, EPS;
- media: MOV/MP4, RIFF/WAV/AVI, ASF, MP3;
- archives: ZIP, RAR, CAB;
- documents: PDF, legacy OLE Office files, RTF, CHM;
- web/text: HTML, JavaScript-like text, CSS-like text, JSON, XML, SVG;
- assorted legacy formats from UnCHK/FileCHK.

Built-in detectors are deliberately conservative where false positives are
common.

## Testing Philosophy

The legacy VB code treated binary data as strings and contained at least one
historical bug in whole-file header matching. This rewrite uses bytes throughout
and includes tests for the behaviors that matter most:

- whole-file detection;
- boundary scanning;
- preserving source files;
- PSD header validation;
- text/code classification;
- targeted carving.

Run the test suite before changing signatures or detection logic:

```powershell
python -m unittest -v test_unchk_modern.py
```

## Safety Notes

- Work on a copy of recovered `CHK` files when possible.
- Keep recovered output outside the source `FOUND.000` directory.
- Prefer `--dry-run` before deeper scan modes.
- Use `--max-copy-mb` when scanning large media fragments.
- Treat recovered files as untrusted input.

## License

See [LICENSE](LICENSE).

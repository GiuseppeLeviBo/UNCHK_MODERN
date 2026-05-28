#!/usr/bin/env python3
"""Tkinter desktop interface for UnCHK Modern."""

from __future__ import annotations

import argparse
import queue
import subprocess
import threading
import tkinter as tk
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import unchk_modern as core


@dataclass
class ScanSettings:
    source: Path
    output: Path
    mode: str
    signatures: Path | None
    filechk_names: bool
    dry_run: bool
    write_log: bool
    max_copy_mb: int
    max_files: int


class UnchkGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("UnCHK Modern")
        self.geometry("900x650")
        self.minsize(760, 560)

        self.worker: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()

        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.signatures_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="whole")
        self.filechk_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=True)
        self.write_log_var = tk.BooleanVar(value=True)
        self.max_copy_var = tk.StringVar(value="512")
        self.max_files_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="Ready")
        self.summary_var = tk.StringVar(value="")

        self._build_ui()
        self.after(100, self._poll_events)

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = ttk.Frame(self, padding=12)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        self._path_row(top, 0, "Source", self.source_var, self._choose_source)
        self._path_row(top, 1, "Output", self.output_var, self._choose_output)
        self._path_row(top, 2, "Signatures", self.signatures_var, self._choose_signatures)

        options = ttk.LabelFrame(self, text="Scan options", padding=12)
        options.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        for column in range(8):
            options.columnconfigure(column, weight=1)

        ttk.Label(options, text="Mode").grid(row=0, column=0, sticky="w")
        mode = ttk.Combobox(options, textvariable=self.mode_var, values=("whole", "harddisk", "floppy", "embedded"), state="readonly", width=12)
        mode.grid(row=0, column=1, sticky="w", padx=(6, 18))

        ttk.Checkbutton(options, text="Only FILE????.CHK", variable=self.filechk_var).grid(row=0, column=2, sticky="w")
        ttk.Checkbutton(options, text="Dry run", variable=self.dry_run_var).grid(row=0, column=3, sticky="w")
        ttk.Checkbutton(options, text="Write log", variable=self.write_log_var).grid(row=0, column=4, sticky="w")

        ttk.Label(options, text="Max copy MiB").grid(row=1, column=0, sticky="w", pady=(10, 0))
        ttk.Entry(options, textvariable=self.max_copy_var, width=8).grid(row=1, column=1, sticky="w", padx=(6, 18), pady=(10, 0))
        ttk.Label(options, text="Max files").grid(row=1, column=2, sticky="w", pady=(10, 0))
        ttk.Entry(options, textvariable=self.max_files_var, width=8).grid(row=1, column=3, sticky="w", padx=(6, 18), pady=(10, 0))

        actions = ttk.Frame(options)
        actions.grid(row=1, column=4, columnspan=4, sticky="e", pady=(10, 0))
        self.start_button = ttk.Button(actions, text="Start scan", command=self._start_scan)
        self.start_button.grid(row=0, column=0, padx=(0, 8))
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self._cancel_scan, state="disabled")
        self.cancel_button.grid(row=0, column=1, padx=(0, 8))
        ttk.Button(actions, text="Open output", command=self._open_output).grid(row=0, column=2)

        body = ttk.Frame(self, padding=(12, 0, 12, 12))
        body.grid(row=2, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        self.progress = ttk.Progressbar(body, mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        log_frame = ttk.LabelFrame(body, text="Log", padding=8)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, wrap="word", height=18)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)

        footer = ttk.Frame(self, padding=(12, 0, 12, 12))
        footer.grid(row=3, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Label(footer, textvariable=self.summary_var).grid(row=0, column=1, sticky="e")

    def _path_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, command) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2, pady=4)

    def _choose_source(self) -> None:
        value = filedialog.askdirectory(title="Select FOUND.000 or CHK source directory")
        if value:
            self.source_var.set(value)
            if not self.output_var.get():
                self.output_var.set(str(Path(value).parent / "recovered_unchk"))

    def _choose_output(self) -> None:
        value = filedialog.askdirectory(title="Select output directory")
        if value:
            self.output_var.set(value)

    def _choose_signatures(self) -> None:
        value = filedialog.askopenfilename(title="Select custom signatures JSON", filetypes=(("JSON files", "*.json"), ("All files", "*.*")))
        if value:
            self.signatures_var.set(value)

    def _settings(self) -> ScanSettings | None:
        source = Path(self.source_var.get()).expanduser()
        output = Path(self.output_var.get()).expanduser()
        if not source.is_dir():
            messagebox.showerror("Invalid source", "Please select a source directory containing CHK files.")
            return None
        if not str(output):
            messagebox.showerror("Invalid output", "Please select an output directory.")
            return None
        signatures = Path(self.signatures_var.get()).expanduser() if self.signatures_var.get().strip() else None
        if signatures and not signatures.is_file():
            messagebox.showerror("Invalid signatures file", "The custom signatures JSON file does not exist.")
            return None
        try:
            max_copy_mb = max(0, int(self.max_copy_var.get() or "0"))
            max_files = max(0, int(self.max_files_var.get() or "0"))
        except ValueError:
            messagebox.showerror("Invalid number", "Max copy MiB and Max files must be whole numbers.")
            return None
        return ScanSettings(
            source=source,
            output=output,
            mode=self.mode_var.get(),
            signatures=signatures,
            filechk_names=self.filechk_var.get(),
            dry_run=self.dry_run_var.get(),
            write_log=self.write_log_var.get(),
            max_copy_mb=max_copy_mb,
            max_files=max_files,
        )

    def _start_scan(self) -> None:
        settings = self._settings()
        if settings is None:
            return
        if self.worker and self.worker.is_alive():
            return

        self.cancel_event.clear()
        self.progress.configure(value=0, maximum=1)
        self.log_text.delete("1.0", "end")
        self.summary_var.set("")
        self.status_var.set("Starting scan...")
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")

        self.worker = threading.Thread(target=self._scan_worker, args=(settings,), daemon=True)
        self.worker.start()

    def _cancel_scan(self) -> None:
        self.cancel_event.set()
        self.status_var.set("Cancelling...")

    def _scan_worker(self, settings: ScanSettings) -> None:
        try:
            signatures = core.default_signatures() + core.load_extra_signatures(settings.signatures)
            files = core.source_files(settings.source, settings.filechk_names)
            if settings.max_files:
                files = files[: settings.max_files]
            if not settings.dry_run:
                settings.output.mkdir(parents=True, exist_ok=True)

            rows: list[dict[str, str]] = []
            recovered = 0
            skipped_large = 0
            unmatched = 0
            errors = 0
            by_match: Counter[str] = Counter()
            max_copy_bytes = settings.max_copy_mb * 1024 * 1024 if settings.max_copy_mb else 0

            self.events.put(("started", len(files)))

            for index, path in enumerate(files, start=1):
                if self.cancel_event.is_set():
                    self.events.put(("log", "Scan cancelled by user."))
                    break

                try:
                    data = path.read_bytes()
                    matches = core.find_matches(data, settings.mode, signatures)
                except OSError as exc:
                    errors += 1
                    rows.append(self._row(path, "error", "", "", "", str(exc)))
                    self.events.put(("log", f"ERROR {path.name}: {exc}"))
                    self.events.put(("progress", (index, recovered, unmatched, skipped_large, errors)))
                    continue

                if not matches:
                    unmatched += 1
                    rows.append(self._row(path, "unmatched", "", "", "", ""))
                else:
                    for match in matches:
                        tail_len = len(data) - match.offset
                        too_large = bool(max_copy_bytes and tail_len > max_copy_bytes)
                        target = core.unique_output_path(settings.output, path, match)
                        if too_large:
                            skipped_large += 1
                            status = "skipped-large"
                        else:
                            target = core.write_match(settings.output, path, data, match, settings.dry_run)
                            recovered += 1
                            status = "dry-run" if settings.dry_run else "recovered"
                        match_name = f"{match.kind}.{match.extension}"
                        by_match[match_name] += 1
                        rows.append(self._row(path, status, match_name, str(match.offset), str(target), f"{match.reason}; tail={tail_len} bytes"))

                if index == len(files) or index % 25 == 0:
                    self.events.put(("progress", (index, recovered, unmatched, skipped_large, errors)))

            if settings.write_log:
                log_path = settings.output / "unchk-modern.log"
                core.write_log(log_path, rows)
                self.events.put(("log", f"Log written: {log_path}"))

            summary = {
                "recovered": recovered,
                "unmatched": unmatched,
                "skipped_large": skipped_large,
                "errors": errors,
                "by_match": by_match.most_common(12),
                "cancelled": self.cancel_event.is_set(),
            }
            self.events.put(("done", summary))
        except Exception as exc:  # noqa: BLE001 - GUI must report unexpected failures.
            self.events.put(("failed", str(exc)))

    def _row(self, source: Path, status: str, match: str, offset: str, output: str, reason: str) -> dict[str, str]:
        return {
            "time": core.datetime.now().isoformat(timespec="seconds"),
            "source": str(source),
            "status": status,
            "match": match,
            "offset": offset,
            "output": output,
            "reason": reason,
        }

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "started":
                    total = int(payload)
                    self.progress.configure(maximum=max(1, total), value=0)
                    self._append_log(f"Scanning {total} CHK file(s).")
                    self.status_var.set("Scanning...")
                elif kind == "progress":
                    index, recovered, unmatched, skipped_large, errors = payload
                    self.progress.configure(value=index)
                    self.status_var.set(f"{index} checked; {recovered} candidates; {unmatched} unmatched; {skipped_large} skipped; {errors} errors")
                elif kind == "log":
                    self._append_log(str(payload))
                elif kind == "done":
                    self._finish_scan(payload)
                elif kind == "failed":
                    self._finish_failed(str(payload))
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _finish_scan(self, summary: dict[str, object]) -> None:
        self.start_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        recovered = summary["recovered"]
        unmatched = summary["unmatched"]
        skipped_large = summary["skipped_large"]
        errors = summary["errors"]
        self.summary_var.set(f"Candidates: {recovered} | Unmatched: {unmatched} | Skipped: {skipped_large} | Errors: {errors}")
        self.status_var.set("Cancelled" if summary["cancelled"] else "Done")
        by_match = summary["by_match"]
        if by_match:
            self._append_log("")
            self._append_log("Top matches:")
            for name, count in by_match:
                self._append_log(f"  {count:5d}  {name}")

    def _finish_failed(self, message: str) -> None:
        self.start_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.status_var.set("Failed")
        messagebox.showerror("Scan failed", message)
        self._append_log(f"FAILED: {message}")

    def _append_log(self, message: str) -> None:
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")

    def _open_output(self) -> None:
        output = self.output_var.get().strip()
        if not output:
            return
        path = Path(output)
        path.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["explorer", str(path)])


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the UnCHK Modern desktop GUI.")
    parser.add_argument("--self-test", action="store_true", help="Import GUI dependencies and exit without opening a window")
    args = parser.parse_args()
    if args.self_test:
        return 0
    app = UnchkGui()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

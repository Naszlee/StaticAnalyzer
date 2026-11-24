#!/usr/bin/env python3
"""
main.py - Static Malware Analyzer (Part 1): CLI, safety framework, PE inspector.

STATIC analysis only. Files are opened read-only and are never executed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ioc_entropy import analyze_entropy_and_iocs
from pe_inspector import NotPE, inspect_pe
from safety import (AbortRequested, KillSwitch, ScopeError, check_output_path,
                    check_scope, confirm_disclaimer, enumerate_targets,
                    ensure_safe_sample, eprint)

__version__ = "1.0.0-part1"

BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
SAFE_SAMPLE = SAMPLES_DIR / "safe_sample.pe"

EXIT_OK = 0
EXIT_ERRORS = 1          # finished, but at least one input could not be analysed
EXIT_DECLINED = 2        # disclaimer not accepted
EXIT_SCOPE = 3           # bad target / out of scope / bad output path
EXIT_ABORTED = 130       # kill switch

EPILOG = """\
examples:
  python main.py
      Analyse the built-in harmless sample (after accepting the disclaimer).

  python main.py --target C:\\Windows\\System32\\notepad.exe --scope-root C:\\Windows\\System32
      Analyse one file; the scope root limits what the tool may touch.

  python main.py -t ./my_samples --recursive --max-files 50
      Analyse every file in a directory tree (scope defaults to current dir).

  python main.py -t ./my_samples --delay 2
      Pause 2s between files - handy for demonstrating the Ctrl+C kill switch.

  python main.py --json -o report.json
      Machine-readable output, also saved to a NEW file (never overwrites).

exit codes: 0 ok | 1 some inputs failed | 2 disclaimer declined | 3 scope/target error | 130 aborted
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Static Malware Analyzer - PE header inspector (Part 1). "
                    "Read-only, never executes the target.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-t", "--target", metavar="PATH",
                   help="file or directory to analyse (default: built-in harmless sample)")
    p.add_argument("--scope-root", metavar="DIR",
                   help="directory the tool is allowed to touch; anything outside is refused "
                        "(default: current directory, or the samples folder for the default target)")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="descend into sub-directories when the target is a directory")
    p.add_argument("--max-files", type=int, default=100, metavar="N",
                   help="maximum number of files to analyse in one run (default: 100)")
    p.add_argument("--max-size-mb", type=float, default=64, metavar="MB",
                   help="skip files larger than this (default: 64)")
    p.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                   help="pause between files (for demonstrating the kill switch)")
    p.add_argument("--json", action="store_true",
                   help="print results as JSON on stdout instead of a text report")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="also save JSON results to FILE (refuses to overwrite)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# --------------------------------------------------------------------------
# Analysis of one file (read-only)
# --------------------------------------------------------------------------
def analyze_file(path: Path, max_bytes: int) -> dict:
    result = {"path": str(path), "status": "ok"}
    try:
        size = path.stat().st_size
        result["size"] = size
        if size > max_bytes:
            result.update(status="error", error=f"Skipped: file is {size} bytes (limit {max_bytes})")
            return result
        with open(path, "rb") as fh:           # READ-ONLY, binary
            data = fh.read()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        try:
            result["md5"] = hashlib.md5(data, usedforsecurity=False).hexdigest()
        except (TypeError, ValueError):
            pass
        try:
            pe_info = inspect_pe(data)
            result["analysis"] = pe_info
            result["entropy_and_iocs"] = analyze_entropy_and_iocs(data, pe_info)
        except NotPE as exc:
            result.update(
                status="error",
                error=f"Not a valid PE file: {exc}",
                entropy_and_iocs=analyze_entropy_and_iocs(data, pe_info=None),
            )
    except (OSError, MemoryError) as exc:
        result.update(status="error", error=f"Cannot read file: {exc}")
    except Exception as exc:                    # last line of defence: never crash
        result.update(status="error", error=f"Unexpected parsing error: {type(exc).__name__}: {exc}")
    return result


# --------------------------------------------------------------------------
# Text report
# --------------------------------------------------------------------------
def _kv(label, value, indent=2):
    return f"{' ' * indent}{label:<26}: {value}"


def format_result(r: dict) -> str:
    out = ["=" * 72, _kv("File", r["path"], 0), _kv("Size", f"{r.get('size', '?')} bytes", 0)]
    if "sha256" in r:
        out.append(_kv("SHA-256", r["sha256"], 0))
    if "md5" in r:
        out.append(_kv("MD5", r["md5"], 0))
    out.append("-" * 72)

    ei = r.get("entropy_and_iocs")
    if ei:
        out.append(f"\n[Entropy & Static IOCs]  (file entropy: {ei['file_entropy']} / {ei['entropy_assessment']})")
        if ei.get("section_entropies"):
            for s in ei["section_entropies"]:
                rwx_tag = " [W+X]" if s.get("rwx") else ""
                out.append(f"  Section {s['name']:<9} entropy={s['entropy']:.4f} ({s['raw_size']} bytes){rwx_tag}")
        iocs = ei.get("iocs", {})
        for key in ("ipv4", "urls", "domains", "emails", "registry_keys", "suspicious_apis"):
            vals = iocs.get(key) or []
            if vals:
                out.append(f"  {key:<16}: {', '.join(vals[:10])}" + (" ..." if len(vals) > 10 else ""))
        for f in ei.get("findings", []):
            out.append(f"  [{f['severity']:<6}] {f['message']}")

    if r["status"] != "ok":
        out.append(f"[!] {r['error']}")
        return "\n".join(out)

    a = r["analysis"]
    d, c, o = a["dos_header"], a["coff_header"], a["optional_header"]

    out.append("[DOS Header]")
    out += [_kv("e_magic", d["e_magic"]),
            _kv("e_cblp / e_cp", f"{d['e_cblp']} / {d['e_cp']}"),
            _kv("e_lfarlc", f"0x{d['e_lfarlc']:X}"),
            _kv("e_lfanew (PE offset)", f"0x{d['e_lfanew']:X}")]

    out.append(f"\n[PE Signature]\n  'PE\\0\\0' found at offset 0x{a['pe_signature_offset']:X}")

    out.append("\n[COFF / File Header]")
    out += [_kv("Machine", f"0x{c['machine']:04X}  {c['machine_name']}"),
            _kv("NumberOfSections", c["number_of_sections"]),
            _kv("TimeDateStamp", f"0x{c['time_date_stamp']:08X}  {c['time_date_stamp_utc']}"),
            _kv("PointerToSymbolTable", f"0x{c['pointer_to_symbol_table']:X}"),
            _kv("NumberOfSymbols", c["number_of_symbols"]),
            _kv("SizeOfOptionalHeader", c["size_of_optional_header"]),
            _kv("Characteristics", f"0x{c['characteristics']:04X}  {', '.join(c['characteristics_flags']) or '-'}")]

    out.append("\n[Optional Header]")
    if o is None:
        out.append("  (not present or not parseable - see warnings)")
    else:
        out += [_kv("Format", f"{o['format']} (magic 0x{o['magic']:X})"),
                _kv("Linker version", f"{o['major_linker_version']}.{o['minor_linker_version']}"),
                _kv("AddressOfEntryPoint", f"0x{o['address_of_entry_point']:X}"
                    + (f"  (in {a['entry_point_section']})" if a["entry_point_section"] else "")),
                _kv("ImageBase", f"0x{o['image_base']:X}"),
                _kv("SectionAlignment", f"0x{o['section_alignment']:X}"),
                _kv("FileAlignment", f"0x{o['file_alignment']:X}"),
                _kv("SizeOfCode", f"0x{o['size_of_code']:X}"),
                _kv("SizeOfImage", f"0x{o['size_of_image']:X}"),
                _kv("SizeOfHeaders", f"0x{o['size_of_headers']:X}"),
                _kv("CheckSum", f"0x{o['checksum']:X}"),
                _kv("Subsystem", f"{o['subsystem']}  {o['subsystem_name']}"),
                _kv("DllCharacteristics", f"0x{o['dll_characteristics']:04X}  "
                    f"{', '.join(o['dll_characteristics_flags']) or '-'}"),
                _kv("NumberOfRvaAndSizes", o["number_of_rva_and_sizes"])]
        if a["data_directories"]:
            out.append("  Data directories (non-empty):")
            for dd in a["data_directories"]:
                out.append(f"    {dd['name']:<24} RVA=0x{dd['rva']:08X}  Size=0x{dd['size']:X}")

    out.append(f"\n[Section Table]  ({len(a['sections'])} parsed)")
    if a["sections"]:
        out.append(f"  {'Name':<9}{'VirtAddr':>10}{'VirtSize':>10}{'RawPtr':>10}{'RawSize':>10}  Perm  Flags")
        for s in a["sections"]:
            name = s["name"] if s["name_printable"] else repr(s["name"])
            perm = ("R" if s["readable"] else "-") + ("W" if s["writable"] else "-") + ("X" if s["executable"] else "-")
            out.append(f"  {name:<9}{s['virtual_address']:>#10x}{s['virtual_size']:>#10x}"
                       f"{s['raw_pointer']:>#10x}{s['raw_size']:>#10x}  {perm}   "
                       f"{', '.join(s['flags']) or '-'}")
    if a["overlay_size"]:
        out.append(_kv("Overlay", f"{a['overlay_size']} bytes at offset 0x{a['overlay_offset']:X}"))

    if a["warnings"]:
        out.append("\n[Parser Warnings]")
        out += [f"  ! {w}" for w in a["warnings"]]

    out.append("\n[Findings]  (heuristic hints, not a malware verdict)")
    if a["findings"]:
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        for f in sorted(a["findings"], key=lambda x: order.get(x["severity"], 9)):
            out.append(f"  [{f['severity']:<6}] {f['message']}")
    else:
        out.append("  none")

    return "\n".join(out)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_files < 1 or args.max_size_mb <= 0 or args.delay < 0:
        eprint("Invalid numeric option (max-files >= 1, max-size-mb > 0, delay >= 0).")
        return EXIT_SCOPE

    # 1) Legal disclaimer FIRST - nothing is touched until the user agrees.
    if not confirm_disclaimer():
        eprint("Disclaimer not accepted. Nothing was analysed. Exiting.")
        return EXIT_DECLINED

    kill = KillSwitch()
    kill.install()

    try:
        # 2) Resolve target + scope
        if args.target is None:
            target = ensure_safe_sample(SAFE_SAMPLE)
            scope_root = Path(args.scope_root) if args.scope_root else SAMPLES_DIR
            eprint(f"[i] No --target given: using the built-in harmless sample\n    {target}")
        else:
            target = Path(args.target)
            scope_root = Path(args.scope_root) if args.scope_root else Path.cwd()

        try:
            target = check_scope(target, scope_root)
            files, notes = enumerate_targets(target, scope_root, args.recursive, args.max_files)
        except ScopeError as exc:
            eprint(f"[X] {exc}")
            return EXIT_SCOPE

        eprint(f"[i] Scope root: {Path(scope_root).resolve()}")
        for n in notes:
            eprint(f"[i] {n}")
        if not files:
            eprint("[X] No files to analyse in the target.")
            return EXIT_ERRORS

        out_path = None
        if args.output:
            try:
                out_path = check_output_path(args.output, files)
            except ScopeError as exc:
                eprint(f"[X] {exc}")
                return EXIT_SCOPE

        # 3) Analyse (read-only), checking the kill switch between files
        max_bytes = int(args.max_size_mb * 1024 * 1024)
        results = []
        for i, path in enumerate(files, 1):
            kill.check()
            eprint(f"[*] ({i}/{len(files)}) Analysing {path.name} ...")
            res = analyze_file(path, max_bytes)
            results.append(res)
            if not args.json:
                print(format_result(res))
            if i < len(files):
                kill.sleep(args.delay)
        kill.check()

        # 4) Output
        failed = sum(1 for r in results if r["status"] != "ok")
        payload = {"tool": "static-malware-analyzer", "version": __version__,
                   "mode": "static, read-only", "results": results}
        if args.json:
            print(json.dumps(payload, indent=2))
        if out_path:
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            eprint(f"[i] JSON report saved to {out_path}")
        eprint(f"\n[done] {len(results) - failed} analysed, {failed} could not be parsed.")
        return EXIT_ERRORS if failed else EXIT_OK

    except (AbortRequested, KeyboardInterrupt):
        eprint("\n[!] Aborted safely. No target file was modified or executed.")
        return EXIT_ABORTED


if __name__ == "__main__":
    sys.exit(main())

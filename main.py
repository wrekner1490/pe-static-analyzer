
import argparse
import json
import sys
import os
from typing import Dict, Any
from datetime import datetime, timezone

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from utils import (read_file_bytes, sha256_of_bytes, md5_of_bytes,
                   entropy_bytes, extract_printable_strings, find_urls, find_paths)
from enrich import extract_utf16_strings, compute_imphash

def get_hashes(data: bytes):
    return {
        "sha256": sha256_of_bytes(data),
        "md5": md5_of_bytes(data),
        "size": len(data)
    }

def parse_imports(binary: lief.PE.Binary):
    imports = []
    for lib in binary.imports:
        try:
            functions = [entry.name for entry in lib.entries if entry.name]
        except Exception:
            
            functions = []
            for entry in lib.entries:
                name = getattr(entry, "name", None)
                if name:
                    functions.append(name)
        imports.append({
            "dll": lib.name,
            "functions": functions
        })
    return imports

def parse_sections(binary: lief.PE.Binary, raw_bytes: bytes):
    sections = []
    for s in binary.sections:
        name = s.name
        size = s.size
        characteristics = s.characteristics
        try:
            content = bytes(s.content)
        except Exception:
            content = b''
            try:
                start = s.offset
                size_real = s.size
                content = raw_bytes[start:start + size_real]
            except Exception:
                content = b''
        ent = entropy_bytes(content)
        sections.append({
            "name": name,
            "virtual_size": s.virtual_size if hasattr(s, "virtual_size") else None,
            "size": size,
            "offset": getattr(s, "offset", None),
            "characteristics": int(characteristics),
            "entropy": ent
        })
    return sections


def analyze_section_anomalies(sections):
    suspicious = []
    for s in sections:
        indicators = []
        ent = s.get("entropy")
        name = (s.get("name") or "").lower()
        characteristics = s.get("characteristics", 0)
        is_write = bool(characteristics & 0x80000000)
        is_execute = bool(characteristics & 0x20000000)

        if ent is not None and ent >= 7.5:
            indicators.append("high_entropy")
        if is_write and is_execute:
            indicators.append("rwx_section")
        if name in {".upx", ".aspack", ".petite", ".mpress"} or name.startswith("upx"):
            indicators.append("packer_like_name")

        if indicators:
            suspicious.append({
                "name": s.get("name"),
                "entropy": ent,
                "characteristics": characteristics,
                "indicators": indicators
            })
    return suspicious

def disassemble_entry(binary: lief.PE.Binary, raw_bytes: bytes, max_instructions=20):
    machine = binary.header.machine
    mode = None
    if "AMD64" in str(machine).upper() or "X86_64" in str(machine).upper() or getattr(lief.PE.MACHINE_TYPES, "AMD64", None) == machine:
        mode = CS_MODE_64
    else:
        mode = CS_MODE_32

    arch = CS_ARCH_X86

    rva = binary.entrypoint
    try:
        offset = binary.rva_to_offset(rva)
    except Exception:
        try:
            offset = binary.virtual_address_to_offset(rva)
        except Exception:
            return {"error": "could not map entrypoint RVA to file offset", "entrypoint_rva": rva}
    start = offset
    snippet = raw_bytes[start:start + 512]

    md = Cs(arch, mode)
    instrs = []
    try:
        for i, insn in enumerate(md.disasm(snippet, rva)):
            if i >= max_instructions:
                break
            instrs.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str
            })
    except Exception as e:
        return {"error": f"capstone disassembly failed: {e}"}

    return {
        "entrypoint_rva": rva,
        "offset": offset,
        "instructions": instrs
    }


def parse_signatures(binary: lief.PE.Binary):
    results = []
    try:
        for sig in getattr(binary, "signatures", []):
            certs = []
            for c in getattr(sig, "certificates", []):
                try:
                    certs.append({
                        "issuer": getattr(c, "issuer", None),
                        "subject": getattr(c, "subject", None),
                        "serial_number": getattr(c, "serial_number", b"")
                        .hex() if hasattr(c, "serial_number") else None,
                        "valid_from": getattr(c, "valid_from", None),
                        "valid_to": getattr(c, "valid_to", None)
                    })
                except Exception:
                    continue
            results.append({
                "version": getattr(sig, "version", None),
                "digest_algorithm": str(getattr(sig, "digest_algorithm", "")),
                "certificates": certs
            })
    except Exception:
        return None
    return results or None


def parse_exports(binary: lief.PE.Binary):
    try:
        if getattr(binary, "has_exports", False):
            exp = binary.get_export()
            return [e.name if e.name else f"ord_{e.ordinal}" for e in getattr(exp, "entries", [])]
    except Exception:
        return []
    return []


def parse_version_info(binary: lief.PE.Binary):
    try:
        if getattr(binary, "has_resources", False):
            rm = binary.resources_manager
            if getattr(rm, "has_version", False):
                vi = rm.version.string_file_info
                values = {}
                for lang in getattr(vi, "langcode_items", []):
                    for k, v in getattr(lang, "items", {}).items():
                        values[k] = v
                return values
    except Exception:
        return {}
    return {}

def build_report(path: str, *, strings_limit: int = 200, do_disasm: bool = True) -> Dict[str, Any]:
    raw = read_file_bytes(path)
    hashes = get_hashes(raw)

    try:
        binary = lief.parse(path)
    except Exception as e:
        return {
            "error": f"failed to parse file with lief: {e}",
            "hashes": hashes
        }

    header = binary.header
    # Basic metadata
    meta = {
        "name": os.path.basename(path),
        "machine": str(header.machine),
        "timestamp": getattr(header, "time_date_stamps", getattr(header, "time_date_stamp", None)),
        "entrypoint": binary.entrypoint
    }

    imports = parse_imports(binary)
    sections = parse_sections(binary, raw)
    suspicious_sections = analyze_section_anomalies(sections)

    strings_ascii = extract_printable_strings(raw)
    strings_utf16 = extract_utf16_strings(raw)
    strings_combined = strings_ascii + strings_utf16
    urls = find_urls(raw)
    paths = find_paths(raw)

    disasm = disassemble_entry(binary, raw) if do_disasm else {"skipped": True}

    # Additional enrichments
    imphash = compute_imphash(path)
    signatures = parse_signatures(binary)
    exports = parse_exports(binary)
    version_info = parse_version_info(binary)

    report = {
        "schema_version": "1.0",
        "tool": {"name": "pe-static-analyzer", "version": "0.1.0"},
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "file": meta,
        "hashes": hashes,
        "imports": imports,
        "sections": sections,
        "strings_sample": strings_combined[: max(0, strings_limit) ],
        "ioc_urls": list(dict.fromkeys(urls)),
        "ioc_paths": list(dict.fromkeys(paths)),
        "disassembly": disasm,
        "suspicious_sections": suspicious_sections,
        "imphash": imphash,
        "exports": exports,
        "version_info": version_info
    }
    if signatures:
        report["signatures"] = signatures
    return report
def main():
    parser = argparse.ArgumentParser(description="Simple PE static analyzer → JSON report")
    parser.add_argument("file", help="PE file path (.exe/.dll)")
    parser.add_argument("-o", "--output", default=None, help="Output JSON file (default: <file>.report.json)")
    parser.add_argument("--strings-limit", type=int, default=200, help="Max number of strings to embed in JSON (default: 200)")
    parser.add_argument("--no-disasm", action="store_true", help="Skip entrypoint disassembly")
    parser.add_argument("--stdout", action="store_true", help="Write report to stdout instead of a file")
    args = parser.parse_args()

    if not args.file or not os.path.isfile(args.file):
        print("Error: input file not found", file=sys.stderr)
        sys.exit(2)

    report = build_report(
        args.file,
        strings_limit=args.strings_limit,
        do_disasm=not args.no_disasm
    )

    if args.stdout:
        print(json.dumps(report, indent=2))
    else:
        outpath = args.output or args.file + ".report.json"
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report written to: {outpath}")

if __name__ == "__main__":
    main()

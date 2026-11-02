# PE Static Analysis Tool

A lightweight **static** analysis utility for Windows PE executables. It parses a
binary without executing it and emits a structured JSON report describing the
file's structure and common indicators — intended for malware-analysis coursework
and triage, not for running untrusted samples.

## What it extracts

- **Hashes & size** — SHA-256, MD5, byte size
- **Imphash** — import-hash for sample clustering
- **Imports** — DLLs and imported functions
- **Sections** — names, sizes, and per-section entropy (packing indicator)
- **Strings** — printable ASCII and UTF-16 strings, with URL and file-path extraction

## Requirements

```
pip install -r requirements.txt
```

- `lief==0.17.0`
- `capstone==5.0.6`
- `pefile==2024.8.26`

## Usage

```bash
python main.py path/to/sample.exe            # prints JSON report to stdout
python main.py path/to/sample.exe -o out.json
```

> Run only in an isolated analysis VM. Static parsing does not execute the file,
> but handle any real-world sample with standard malware-handling precautions.

## Files

- `main.py` — entrypoint; PE parsing and report assembly (lief + capstone)
- `utils.py` — hashing, entropy, string/URL/path extraction helpers
- `enrich.py` — UTF-16 string extraction and imphash computation

## Project status

Course / research project. Static analysis path is complete and produces reports
for standard PE files.

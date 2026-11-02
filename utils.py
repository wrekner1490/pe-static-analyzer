import math
import re
from collections import Counter
import hashlib

PRINTABLE_RE = re.compile(rb'[\x20-\x7E]{4,}')
URL_RE = re.compile(rb'(https?://[^\s\'"<>]+)', re.IGNORECASE)
PATH_RE = re.compile(rb'([A-Za-z]:\\[^ \t\n\r\'"]+)', re.IGNORECASE)

def entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent

def extract_printable_strings(data: bytes, min_len: int = 4):
    return [m.group(0).decode('latin-1', errors='ignore') for m in PRINTABLE_RE.finditer(data)]

def find_urls(data: bytes):
    return [m.group(0).decode('latin-1', errors='ignore') for m in URL_RE.finditer(data)]

def find_paths(data: bytes):
    return [m.group(0).decode('latin-1', errors='ignore') for m in PATH_RE.finditer(data)]

def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def md5_of_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def read_file_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

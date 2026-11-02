import re
from typing import List, Optional

import pefile

UTF16_RE = re.compile(rb'(?:[\x20-\x7E]\x00){4,}')


def extract_utf16_strings(data: bytes, min_len: int = 4) -> List[str]:
    results: List[str] = []
    for match in UTF16_RE.finditer(data):
        try:
            s = match.group(0).decode('utf-16le', errors='ignore')
        except Exception:
            continue
        if len(s) >= min_len:
            results.append(s)
    return results


def compute_imphash(path: str) -> Optional[str]:
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        )
        return pe.get_imphash()
    except Exception:
        return None



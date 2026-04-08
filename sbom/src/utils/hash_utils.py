from pathlib import Path
import hashlib
from typing import Dict, List


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def cyclonedx_hash_obj(value: str) -> Dict[str, str]:
    return {"alg": "SHA-256", "content": value}


def hashes_for_files(paths: List[str]) -> List[Dict[str, str]]:
    out = []
    for p in paths or []:
        try:
            val = sha256_of_file(Path(p))
            out.append(cyclonedx_hash_obj(val))
        except Exception:
            continue
    return out

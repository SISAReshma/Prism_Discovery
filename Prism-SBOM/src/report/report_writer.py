# File: src/report/report_writer.py
from pathlib import Path
import json
from typing import Dict, Any, Tuple, Optional

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _write_json_file(path: Path, data: Any) -> None:
    # If data is already a string, try to detect if it's JSON (best-effort), otherwise write as-is.
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    elif isinstance(data, str):
        # try parse string to JSON to pretty print, else write raw string
        try:
            parsed = json.loads(data)
            path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            path.write_text(data, encoding="utf-8")
    else:
        # fallback generic serialization
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def write_reports(artifacts: Dict[str, Any], reports_dir: Path, scan_id: str) -> Dict[str, Dict[str, Path]]:
    """
    Write SBOM and AIBOM artifacts into separate folders and return dict of paths.

    Expected `artifacts` shape (flexible):
    {
      "sbom": {
         "spdx": <dict|string>,
         "cyclonedx": <dict|string>,
         "json": <dict|string>
      }
    }

    The function will create:
      reports_dir/<scan_id>/...

    Returns:
    {
      "sbom": {"spdx": Path(...), "cyclonedx": Path(...), "json": Path(...) }
    }
    """
    reports_dir = Path(reports_dir)
    sbom_out = {}

    # Helper to obtain artifact content safely
    def _get_artifact_section(name: str) -> Dict[str, Any]:
        # tolerate top-level being the sbom content itself
        if not artifacts:
            return {}
        if name in artifacts and isinstance(artifacts[name], dict):
            return artifacts.get(name, {})
        # sometimes generate_all might return a flat dict with keys 'spdx','cyclonedx','json' for SBOM
        # treat the top-level as sbom if it contains spdx
        if name == "sbom" and ("spdx" in artifacts or "cyclonedx" in artifacts or "json" in artifacts):
            return {
                "spdx": artifacts.get("spdx"),
                "cyclonedx": artifacts.get("cyclonedx"),
                "json": artifacts.get("json"),
            }
        return {}

    sbom_section = _get_artifact_section("sbom")

    # Write SBOM files directly to reports_dir/scan_id/
    sbom_base = reports_dir / scan_id
    _ensure_dir(sbom_base)
    # expected keys and filenames
    mapping = [
        ("spdx", f"{scan_id}.spdx.json"),
        ("cyclonedx", f"{scan_id}.cyclonedx.json"),
        ("json", f"{scan_id}.json.json"),
    ]
    for key, fname in mapping:
        content = sbom_section.get(key)
        if content is None:
            # skip if not present
            continue
        outp = sbom_base / fname
        _write_json_file(outp, content)
        sbom_out[key] = outp



    # In addition: if SBOM/AIBOM sections empty, still return empty dicts
    result = {
        "sbom": sbom_out
    }
    return result

#!/usr/bin/env python3
"""
Unified AIBOM + SBOM CLI — PrismAIBOM Scanner

Runs both the AI Bill of Materials (AIBOM) and Software Bill of Materials (SBOM)
pipelines from the command line, producing result files for both.

Usage:
    python cli.py --repo https://github.com/owner/repo
    python cli.py --repo https://github.com/owner/repo --token ghp_xxx
    python cli.py --local /path/to/project
    python cli.py --local /path/to/project --mode aibom
    python cli.py --local /path/to/project --mode sbom
    python cli.py --local /path/to/project --mode both   (default)

Output:
    reports/<scan_id>/
        <scan_id>_aibom.json          (CycloneDX AI BOM)
        <scan_id>.spdx.json           (SPDX 2.3)
        <scan_id>.cyclonedx.json      (CycloneDX 1.5)
        <scan_id>.json.json           (Raw JSON SBOM)
        remediation report

The AIBOM pipeline replaces FastAPI session-based data flow with an in-memory
dictionary (pipeline_data) that accumulates results step by step.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, Set, List, Dict, Any

# Ensure app/ is on sys.path so all imports work
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

# Load environment variables
_env_path = ROOT / ".env"
if _env_path.exists():
    load_dotenv(_env_path, override=False)
elif (ROOT / "aibom" / "src" / ".env").exists():
    load_dotenv(ROOT / "aibom" / "src" / ".env", override=False)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s - %(message)s",
    force=True,
)
logger = logging.getLogger("prismaibom.cli")


# =============================================================================
# AIBOM IMPORTS (same modules used by main.py endpoints)
# =============================================================================
from aibom.config import CODE_FILE_EXTENSIONS, SKIP_DIRECTORIES
from aibom.src.manifest_parser import analyze_packages as do_analyze_packages
from aibom.src.semgrep_scanner import scan_and_dedupe, filter_local_imports, extract_packages_with_sources
from aibom.src.package_resolver import resolve_and_compare
from aibom.src.dependency_graph import build_dependency_graph
from aibom.src.llm_validator import validate_libraries
from aibom.src.llm_categorizer import run_categorization
from aibom.src.ai_branch_tracer import trace_ai_branches
from aibom.src.ai_targeted_scanner import scan_ai_branches, scan_api_branches

from aibom.src.model_deprecation_checker import check_models_deprecation
from aibom.src.aibom_connector import build_aibom
from aibom.src.combined_report import build_combined_report

# =============================================================================
# SBOM IMPORTS
# =============================================================================
from sbom.src.core.orchestrator import ScanOrchestrator


# =============================================================================
# HELPERS (mirroring main.py utility functions)
# =============================================================================

def collect_files(source_path: str) -> List[str]:
    """Walk directory and collect all non-hidden files, skipping common dirs."""
    files_list = []
    for root, dirs, files in os.walk(source_path):
        dirs[:] = [d for d in dirs if d[0] != "." and d not in SKIP_DIRECTORIES]
        for file in files:
            if file[0] != ".":
                rel_path = os.path.relpath(os.path.join(root, file), source_path)
                files_list.append(rel_path.replace("\\", "/"))
    return files_list


def validate_source(source: str, source_type: str, token: Optional[str] = None) -> str:
    """
    Validate and prepare the source path.
    For repos: clone via AIBOM validate.
    For local: verify path exists.
    Returns the absolute local path to the source.
    """
    if source_type == "repo":
        from aibom.src.validate import parse_github_url, check_repo_exists, clone_repo
        owner, repo, url_error = parse_github_url(source)
        if url_error:
            raise SystemExit(f"Invalid repository URL: {url_error}")

        print(f"  Checking repository {owner}/{repo}...")
        check = check_repo_exists(owner, repo, token)
        if check.get("error"):
            raise SystemExit(f"Repository check failed: {check['error']}")
        if not check["exists"]:
            raise SystemExit(f"Repository not found: {owner}/{repo}")

        print(f"  Cloning repository {owner}/{repo}...")
        try:
            clone_path, details = clone_repo(owner, repo, token)
        except Exception as e:
            raise SystemExit(f"Clone failed: {e}")

        print(f"  Cloned to: {clone_path} ({details['file_count']} files)")
        return clone_path

    elif source_type == "local":
        resolved = os.path.abspath(source)
        if not os.path.exists(resolved):
            raise SystemExit(f"Path does not exist: {source}")
        if not os.path.isdir(resolved):
            raise SystemExit(f"Path is not a directory: {source}")
        return resolved

    elif source_type == "zip":
        # For ZIP, extract using SBOM workspace (the SBOM orchestrator handles this)
        zip_path = Path(source).resolve()
        if not zip_path.exists():
            raise SystemExit(f"ZIP file not found: {source}")
        return str(zip_path)

    else:
        raise SystemExit(f"Unknown source type: {source_type}")


# =============================================================================
# AIBOM PIPELINE (mirrors main.py endpoints, uses in-memory dict)
# =============================================================================

def run_aibom_pipeline(source_path: str, output_dir: Path) -> Optional[str]:
    """
    Run the complete AIBOM discovery pipeline.

    Mirrors the 15-step FastAPI endpoint chain from main.py, replacing
    session.extra with a plain Python dictionary (pipeline_data).

    Returns the path to the generated AIBOM CycloneDX JSON file, or None on failure.
    """
    pipeline_data: Dict[str, Any] = {
        "local_path": source_path,
    }

    total_steps = 14
    aibom_output_path = None

    def step(num: int, name: str):
        print(f"  [{num}/{total_steps}] {name}")

    try:
        # ================================================================
        # STEP 1: Validate source (already done — path is ready)
        # ================================================================
        step(1, "Source validated")

        # ================================================================
        # STEP 2: List all files
        # ================================================================
        step(2, "Listing files...")
        files_list = collect_files(source_path)
        pipeline_data["files_list"] = files_list
        print(f"           Found {len(files_list)} files")

        # ================================================================
        # STEP 3: Extract code tokens
        # ================================================================
        step(3, "Extracting code tokens...")
        tokens: Set[str] = set()
        code_files_processed = 0
        for file_path in files_list:
            ext = Path(file_path).suffix.lower()
            if ext in CODE_FILE_EXTENSIONS:
                code_files_processed += 1
                parts = Path(file_path).parts
                for part in parts[:-1]:
                    tokens.add(part)
                tokens.add(Path(file_path).stem)

        sorted_tokens = sorted(tokens)
        pipeline_data["code_tokens"] = sorted_tokens
        pipeline_data["code_tokens_set"] = set(sorted_tokens)
        print(f"           {len(sorted_tokens)} unique tokens from {code_files_processed} code files")

        # ================================================================
        # STEP 4: Analyze packages (detect languages + parse manifests)
        # ================================================================
        step(4, "Analyzing packages & manifests...")
        checkout_path = Path(source_path)
        result = do_analyze_packages(checkout_path, files_list)

        pipeline_data["languages_detected"] = result["languages_detected"]
        pipeline_data["manifests_found"] = result["manifests_found"]
        pipeline_data["dependencies"] = result["dependencies"]
        print(f"           Languages: {result['languages_detected']}, "
              f"Dependencies: {result['summary']['total_dependencies']}")

        # ================================================================
        # STEP 5: Semgrep imports scan
        # ================================================================
        step(5, "Running Semgrep import detection...")
        languages_detected = pipeline_data["languages_detected"]

        try:
            semgrep_result = scan_and_dedupe(source_path, set(languages_detected))
        except FileNotFoundError:
            logger.warning("Semgrep not installed — skipping import detection")
            semgrep_result = {
                "scan_results": {},
                "summary": {"total_third_party": 0, "total_builtin": 0, "total_relative": 0}
            }

        pipeline_data["semgrep_scan_results"] = semgrep_result["scan_results"]
        pipeline_data["imports_files_scanned"] = semgrep_result["summary"].get("files_scanned", [])
        pipeline_data["imports_files_scanned_count"] = semgrep_result["summary"].get("files_scanned_count", 0)
        print(f"           {semgrep_result['summary']['total_third_party']} third-party, "
              f"{semgrep_result['summary']['total_builtin']} builtin imports")

        # ================================================================
        # STEP 6: Resolve packages (manifest → import mapping)
        # ================================================================
        step(6, "Resolving packages...")
        scan_results = pipeline_data["semgrep_scan_results"]
        dependencies = pipeline_data["dependencies"]

        # Build import_packages dict from scan_results (same as main.py)
        import_packages: Dict[str, list] = {
            "python_imports": [],
            "javascript_imports": [],
            "go_imports": [],
            "dotnet_imports": [],
            "java_imports": [],
        }

        lang_key_map = {
            "python": "python_imports",
            "javascript": "javascript_imports",
            "go": "go_imports",
            "dotnet": "dotnet_imports",
            "java": "java_imports",
        }

        for lang, key in lang_key_map.items():
            if lang in scan_results:
                for imp in scan_results[lang].get("third_party", []):
                    import_packages[key].append({
                        "package": imp.get("base_package") or imp.get("import_name") or imp.get("module", ""),
                        "source_files": [imp.get("file", "")],
                        "import_details": [{
                            "module": imp.get("module", ""),
                            "imported_item": imp.get("imported_item") or None,
                            "file": imp.get("file", ""),
                            "line": imp.get("line", 0),
                        }]
                    })

        resolve_result = resolve_and_compare(
            manifest_packages=dependencies,
            semgrep_imports=import_packages,
            languages=languages_detected
        )

        pipeline_data["resolved_packages"] = resolve_result
        pipeline_data["import_packages"] = import_packages
        print(f"           {len(resolve_result.get('resolved_packages', []))} resolved, "
              f"{len(resolve_result.get('used_libraries', []))} used, "
              f"{len(resolve_result.get('unused_libraries', []))} unused")

        # ================================================================
        # STEP 7: Filtered imports (remove local imports)
        # ================================================================
        step(7, "Filtering local imports...")
        code_tokens_set = pipeline_data["code_tokens_set"]

        filtered_results = filter_local_imports(scan_results, code_tokens_set)
        filtered_import_packages = extract_packages_with_sources(filtered_results, set(languages_detected))

        pipeline_data["filtered_imports"] = filtered_results
        pipeline_data["import_packages"] = filtered_import_packages

        unique_packages = sum(
            len(filtered_import_packages.get(k, []))
            for k in lang_key_map.values()
        )
        print(f"           {unique_packages} unique external packages")

        # ================================================================
        # STEP 8: Dependency graph
        # ================================================================
        step(8, "Building dependency graph...")
        graph = build_dependency_graph(scan_results, code_tokens_set)
        pipeline_data["dependency_graph"] = graph
        print(f"           {graph['metadata']['total_files']} files, "
              f"{graph['metadata']['total_dependencies']} dependencies")

        # ================================================================
        # STEP 9: LLM validation (classify AI vs non-AI)
        # ================================================================
        step(9, "LLM validation (AI vs non-AI classification)...")
        try:
            llm_result = validate_libraries(
                dependencies,
                filtered_import_packages,
                resolve_result,
                pipeline_data.get("manifests_found", {})
            )

            if llm_result is None:
                raise ValueError("LLM validation returned no results")

            pipeline_data["llm_validation"] = llm_result
            pipeline_data["ai_libraries"] = llm_result.get("ai_libraries", [])
            pipeline_data["api_libraries"] = llm_result.get("api_libraries", [])
            print(f"           {llm_result['total_classified']} classified, "
                  f"{llm_result['total_ai_positive']} AI-positive, "
                  f"{llm_result['total_api_positive']} API-positive")

        except Exception as e:
            logger.warning(f"LLM validation failed (non-fatal): {e}")
            print(f"           SKIPPED — LLM unavailable ({e})")
            pipeline_data["llm_validation"] = {
                "ai_libraries": [], "api_libraries": [], "non_ai_libraries": [],
                "total_classified": 0, "total_ai_positive": 0,
                "total_api_positive": 0, "total_non_ai": 0,
                "model_used": "none"
            }
            pipeline_data["ai_libraries"] = []
            pipeline_data["api_libraries"] = []

        # ================================================================
        # STEP 10: LLM categorization
        # ================================================================
        step(10, "LLM categorization (AI/API library types)...")
        ai_libraries = pipeline_data.get("ai_libraries", [])
        api_libraries = pipeline_data.get("api_libraries", [])

        if not ai_libraries and not api_libraries:
            print("           No AI or API libraries to categorize")
            pipeline_data["llm_categorization"] = {
                "ai_categories": {}, "api_categories": {},
                "total_ai_libraries": 0, "total_api_libraries": 0,
                "model_used": "none", "by_category": {}, "total_libraries": 0,
            }
        else:
            try:
                cat_result = run_categorization(ai_libraries, api_libraries)
                if not cat_result:
                    raise ValueError("Categorization returned no results")
                pipeline_data["llm_categorization"] = cat_result
                print(f"           {cat_result['total_ai_libraries']} AI + "
                      f"{cat_result['total_api_libraries']} API categorized")
            except Exception as e:
                logger.warning(f"LLM categorization failed (non-fatal): {e}")
                print(f"           SKIPPED — {e}")
                pipeline_data["llm_categorization"] = {
                    "ai_categories": {}, "api_categories": {},
                    "total_ai_libraries": 0, "total_api_libraries": 0,
                    "model_used": "none", "by_category": {}, "total_libraries": 0,
                }

        # ================================================================
        # STEP 11: AI branch trace
        # ================================================================
        step(11, "Tracing AI + API library branches...")
        if "llm_categorization" not in pipeline_data or "dependency_graph" not in pipeline_data:
            print("           SKIPPED — missing prerequisites")
            pipeline_data["ai_branch_trace"] = {"branches": {}, "api_branches": {}, "summary": {}, "api_summary": {}}
        else:
            try:
                trace_result = trace_ai_branches(
                    checkout_dir=source_path,
                    dependency_graph=pipeline_data["dependency_graph"],
                    categorization_data=pipeline_data["llm_categorization"]
                )
                pipeline_data["ai_branch_trace"] = trace_result
                ai_count = trace_result.get("summary", {}).get("total_branches", 0)
                api_count = trace_result.get("api_summary", {}).get("total_branches", 0)
                print(f"           {ai_count} AI branches + {api_count} API branches")
            except Exception as e:
                logger.warning(f"AI branch trace failed (non-fatal): {e}")
                print(f"           SKIPPED — {e}")
                pipeline_data["ai_branch_trace"] = {"branches": {}, "api_branches": {}, "summary": {}, "api_summary": {}}

        # ================================================================
        # STEP 12: AI targeted scan (semgrep model detection)
        # ================================================================
        step(12, "Targeted semgrep scan (model detection)...")
        if "ai_branch_trace" not in pipeline_data:
            print("           SKIPPED — missing AI branch trace")
            pipeline_data["ai_targeted_scan"] = {"scan_results": [], "models_detected": [], "distinct_models": [], "summary": {}}
        else:
            try:
                branch_trace = pipeline_data["ai_branch_trace"]

                # AI scan pass
                ai_scan_result = scan_ai_branches(
                    checkout_dir=source_path,
                    branch_trace=branch_trace,
                    languages_detected=languages_detected
                )

                # API scan pass
                api_scan_result = scan_api_branches(
                    checkout_dir=source_path,
                    branch_trace=branch_trace,
                    languages_detected=languages_detected
                )

                combined = {**ai_scan_result, **api_scan_result}
                pipeline_data["ai_targeted_scan"] = combined

                models_count = ai_scan_result.get("summary", {}).get("unique_models_detected", 0)
                findings_count = ai_scan_result.get("summary", {}).get("total_findings", 0)
                print(f"           {findings_count} findings, {models_count} models detected")

            except FileNotFoundError:
                logger.warning("Semgrep not installed — skipping targeted scan")
                print("           SKIPPED — Semgrep not installed")
                pipeline_data["ai_targeted_scan"] = {"scan_results": [], "models_detected": [], "distinct_models": [], "summary": {}}
            except Exception as e:
                logger.warning(f"AI targeted scan failed (non-fatal): {e}")
                print(f"           SKIPPED — {e}")
                pipeline_data["ai_targeted_scan"] = {"scan_results": [], "models_detected": [], "distinct_models": [], "summary": {}}

        # ================================================================
        # STEP 13: Model deprecation check
        # ================================================================
        step(13, "Checking model deprecation status...")
        distinct_models = pipeline_data.get("ai_targeted_scan", {}).get("distinct_models", [])
        if not distinct_models:
            print("           No models to check")
            pipeline_data["model_deprecation_results"] = {"models_checked": 0, "deprecated_count": 0, "results": []}
        else:
            try:
                dep_result = check_models_deprecation(distinct_models)
                pipeline_data["model_deprecation_results"] = dep_result
                print(f"           {dep_result.get('models_checked', 0)} checked, "
                      f"{dep_result.get('deprecated_count', 0)} deprecated")
            except Exception as e:
                logger.warning(f"Model deprecation check failed (non-fatal): {e}")
                print(f"           SKIPPED — {e}")
                pipeline_data["model_deprecation_results"] = {"models_checked": 0, "deprecated_count": 0, "results": []}

        # ================================================================
        # STEP 14: AIBOM Connector (assemble final CycloneDX AI BOM)
        # ================================================================
        step(14, "Building CycloneDX AI BOM...")
        try:
            hf_token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")

            # build_aibom expects session.extra — we pass pipeline_data as the equivalent
            aibom_result = build_aibom(
                session_extra=pipeline_data,
                hf_token=hf_token,
            )

            pipeline_data["aibom_connector"] = aibom_result

            meta = aibom_result.get("_connector_meta", {})
            print(f"           {meta.get('models_processed', 0)} models, "
                  f"{meta.get('models_found', 0)} found")

            # Save AIBOM CycloneDX to file
            output_dir.mkdir(parents=True, exist_ok=True)
            aibom_output_path = str(output_dir / "aibom_cyclonedx.json")

            with open(aibom_output_path, "w", encoding="utf-8") as f:
                json.dump(aibom_result, f, indent=2, default=str)

            print(f"           Saved to: {aibom_output_path}")

        except Exception as e:
            logger.error(f"AIBOM connector failed: {e}")
            print(f"           FAILED — {e}")
            import traceback
            traceback.print_exc()

    except KeyboardInterrupt:
        print("\n\n[!] AIBOM pipeline interrupted by user.")
        return None
    except Exception as e:
        logger.error(f"AIBOM pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        return None

    return aibom_output_path


# =============================================================================
# SBOM PIPELINE (delegates to existing ScanOrchestrator)
# =============================================================================

def run_sbom_pipeline(
    source: str,
    source_type: str,
    reports_dir: Path,
    token: Optional[str] = None,
    username: Optional[str] = None,
    project_name: Optional[str] = None,
) -> dict:
    """
    Run the SBOM scanning pipeline using the existing ScanOrchestrator.

    Returns a dict with report paths and scan result info.
    """
    # Use OS temp dir so cloned/extracted workspaces never land inside the
    # reports folder.  The orchestrator cleans each scan's subdirectory on
    # completion; the parent dir (prism_sbom_temp) is harmless OS-temp debris.
    _sbom_temp = Path(tempfile.gettempdir()) / "prism_sbom_temp"
    orchestrator = ScanOrchestrator(
        reports_dir=str(reports_dir),
        temp_dir=str(_sbom_temp)
    )

    result = orchestrator.run_scan(
        source=source,
        source_type=source_type,
        token=token,
        username=username,
        project_name=project_name,
        cleanup_after=(source_type != "local"),  # Don't cleanup local paths
    )

    return {
        "scan_id": result.scan_id,
        "success": result.success,
        "packages_count": len(result.packages),
        "vulnerabilities_count": result.vulnerabilities_count,
        "reports": result.reports,
        "remediation_path": result.remediation_path,
        "errors": result.errors,
        "warnings": result.warnings,
        "duration_seconds": result.duration_seconds,
    }


# =============================================================================
# ARGUMENT PARSING
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        prog="prism-scanner",
        description="Unified AIBOM + SBOM Scanner — produces both AI BOM and Software BOM results.",
        epilog="Examples:\n"
               "  python cli.py --repo https://github.com/pallets/flask\n"
               "  python cli.py --local /path/to/project --mode aibom\n"
               "  python cli.py --local /path/to/project --mode both\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Source input
    src_group = p.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--repo", help="Git repository URL (https or ssh).")
    src_group.add_argument("--local", help="Local path to a folder to scan.")
    src_group.add_argument("--zip", help="Path to a .zip file to scan.")

    # Authentication
    p.add_argument("--token", help="Personal Access Token for private repos.", default=None)
    p.add_argument("--username", help="Username for auth (some providers).", default=None)

    # Mode selection
    p.add_argument(
        "--mode",
        choices=["both", "aibom", "sbom"],
        default="both",
        help="Which pipeline(s) to run: 'both' (default), 'aibom', or 'sbom'."
    )

    # Output
    p.add_argument("--reports-dir", default="reports", help="Base reports directory (default: reports).")

    return p.parse_args()


# =============================================================================
# MAIN
# =============================================================================

def _next_scan_number(reports_dir: Path) -> int:
    """Get the next sequential scan number by looking at existing folders."""
    max_num = 0
    if reports_dir.exists():
        for item in reports_dir.iterdir():
            if item.is_dir() and item.name.isdigit():
                max_num = max(max_num, int(item.name))
    return max_num + 1


def main():
    args = parse_args()
    start_time = time.time()

    # Determine source
    if args.repo:
        source = args.repo
        source_type = "repo"
    elif args.local:
        source = args.local
        source_type = "local"
    elif args.zip:
        source = args.zip
        source_type = "zip"
    else:
        raise SystemExit("No source provided. Use --repo, --local, or --zip.")

    # Derive project name
    if args.repo:
        project_name = source.rstrip("/").split("/")[-1].replace(".git", "")
    elif args.local:
        project_name = Path(args.local).name
    elif args.zip:
        project_name = Path(args.zip).stem
    else:
        project_name = "UNKNOWN"

    reports_dir = Path(args.reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)

    run_aibom = args.mode in ("both", "aibom")
    run_sbom = args.mode in ("both", "sbom")

    # Sequential scan number (1, 2, 3, ...)
    scan_num = _next_scan_number(reports_dir)
    scan_id = str(scan_num)
    output_dir = reports_dir / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"  PrismAIBOM Unified Scanner")
    print(f"{'=' * 60}")
    print(f"  Source:  {source}")
    print(f"  Type:    {source_type}")
    print(f"  Mode:    {args.mode}")
    print(f"  Report:  {output_dir}")
    print(f"{'=' * 60}\n")

    # ── Validate source ──
    print("[SOURCE] Validating source...")
    if source_type == "zip" and run_aibom:
        # For ZIP + AIBOM, we need to extract first so AIBOM can scan the files
        import zipfile, tempfile, shutil
        zip_path = Path(source).resolve()
        if not zip_path.exists():
            raise SystemExit(f"ZIP file not found: {source}")

        temp_extract = Path(tempfile.mkdtemp(prefix="prism_cli_"))
        print(f"  Extracting ZIP to {temp_extract}...")
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            zf.extractall(str(temp_extract))
        local_path = str(temp_extract)
    else:
        local_path = validate_source(source, source_type, args.token)

    print(f"[SOURCE] Ready: {local_path}\n")

    # ── AIBOM Pipeline ──
    aibom_path = None
    if run_aibom:
        print(f"{'=' * 60}")
        print(f"  AIBOM Pipeline — AI Bill of Materials")
        print(f"{'=' * 60}")
        aibom_start = time.time()
        aibom_path = run_aibom_pipeline(local_path, output_dir)
        aibom_duration = time.time() - aibom_start
        if aibom_path:
            print(f"\n  [OK] AIBOM completed in {aibom_duration:.2f}s")
        else:
            print(f"\n  [WARN] AIBOM pipeline completed with issues ({aibom_duration:.2f}s)")
        print()

    # ── SBOM Pipeline ──
    sbom_result = None
    sbom_cdx_path = None
    if run_sbom:
        print(f"{'=' * 60}")
        print(f"  SBOM Pipeline — Software Bill of Materials")
        print(f"{'=' * 60}")
        sbom_start = time.time()

        # For SBOM, we pass the original source and let the orchestrator handle it
        if source_type in ("repo", "zip"):
            sbom_source = local_path
            sbom_source_type = "local"
        else:
            sbom_source = local_path
            sbom_source_type = "local"

        # Use a separate temp directory for SBOM output to avoid file collisions
        # with our numbered folder (the orchestrator creates its own scan_id subfolder)
        sbom_reports_dir = reports_dir / "_sbom_temp"
        sbom_reports_dir.mkdir(parents=True, exist_ok=True)

        sbom_result = run_sbom_pipeline(
            source=sbom_source,
            source_type=sbom_source_type,
            reports_dir=sbom_reports_dir,
            token=args.token,
            username=args.username,
            project_name=project_name,
        )
        sbom_duration = time.time() - sbom_start

        if sbom_result["success"]:
            print(f"\n  [OK] SBOM completed in {sbom_duration:.2f}s")

            # Copy only the CycloneDX output into our numbered folder
            src_cdx = sbom_result["reports"].get("cyclonedx")
            if src_cdx and Path(src_cdx).exists():
                import shutil
                sbom_cdx_path = str(output_dir / "sbom_cyclonedx.json")
                shutil.copy2(src_cdx, sbom_cdx_path)
                print(f"  Saved to: {sbom_cdx_path}")

            # Clean up the temp SBOM output directory
            try:
                import shutil
                shutil.rmtree(str(sbom_reports_dir), ignore_errors=True)
            except Exception:
                pass
        else:
            print(f"\n  [ERROR] SBOM failed: {', '.join(sbom_result['errors'])}")
        print()

    # ── Combined Report ──
    combined_path = None
    if aibom_path or sbom_cdx_path:
        print(f"{'=' * 60}")
        print(f"  Generating Combined Report")
        print(f"{'=' * 60}")

        # Load AIBOM data
        aibom_data = None
        if aibom_path and Path(aibom_path).exists():
            try:
                with open(aibom_path, "r", encoding="utf-8") as f:
                    aibom_data = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load AIBOM for combined report: {e}")

        # Load SBOM CycloneDX data
        sbom_data = None
        if sbom_cdx_path and Path(sbom_cdx_path).exists():
            try:
                with open(sbom_cdx_path, "r", encoding="utf-8") as f:
                    sbom_data = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load SBOM for combined report: {e}")

        combined = build_combined_report(
            aibom_data=aibom_data,
            sbom_data=sbom_data,
            scan_id=scan_id,
            project_name=project_name,
        )

        combined_path = str(output_dir / "combined.json")
        with open(combined_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, default=str)

        print(f"  Saved to: {combined_path}")
        print()

    # ── Summary ──
    total_duration = time.time() - start_time
    print(f"{'=' * 60}")
    print(f"  SCAN COMPLETED")
    print(f"{'=' * 60}")
    print(f"  Scan #:   {scan_id}")
    print(f"  Duration: {total_duration:.2f} seconds")
    print(f"  Output:   {output_dir}")
    print()

    print("  Reports Generated:")
    if aibom_path:
        print(f"    - {output_dir / 'aibom_cyclonedx.json'}")
    if sbom_cdx_path:
        print(f"    - {output_dir / 'sbom_cyclonedx.json'}")
    if combined_path:
        print(f"    - {output_dir / 'combined.json'}")

    if sbom_result and sbom_result["success"]:
        print()
        print(f"  SBOM Summary:")
        print(f"    Packages found:    {sbom_result['packages_count']}")
        print(f"    Vulnerabilities:   {sbom_result['vulnerabilities_count']}")

    print(f"\n{'=' * 60}\n")

    # Cleanup temp ZIP extraction if created by us
    if source_type == "zip" and run_aibom:
        try:
            import shutil
            if "temp_extract" in dir() and Path(local_path).exists():
                shutil.rmtree(local_path, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# File: cli/sbom_cli.py
"""
StackSQScanner CLI - SBOM Scanner with CERT-IN Compliance

Usage:
    python cli/sbom_cli.py --repo https://github.com/pallets/flask
    python cli/sbom_cli.py --repo https://github.com/django/django --token ghp_xxx
    python cli/sbom_cli.py --local /path/to/project
    python cli/sbom_cli.py --zip /path/to/archive.zip

Features:
    - Supported ecosystems: Python (PyPI) and npm (JavaScript/Node) ONLY
    - Vulnerability scanning (OSV.dev + NVD)
    - SBOM generation (SPDX 2.3, CycloneDX 1.5, JSON)
    - CERT-IN PURL format (pkg:ecosystem/Package@version)
    - Metadata enrichment (deps.dev for license/homepage, registry APIs for description/supplier/hashes)
    
Now uses the unified Orchestrator for the complete pipeline.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
import uuid
from datetime import datetime, timezone
from getpass import getpass
from typing import Optional, Tuple, Dict, Any
from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import the unified orchestrator
from src.core.orchestrator import ScanOrchestrator, ScanResult
from src.utils.file_utils import ensure_dir
from src.utils.git_utils import probe_repo_access, verify_pat


def get_next_scan_number(reports_dir: Path) -> int:
    """
    Get the next sequential scan number by checking existing report folders.
    
    Args:
        reports_dir: Path to reports directory
    
    Returns:
        Next available scan number (e.g., 1, 2, 3... 91, 92, 93...)
    """
    if not reports_dir.exists():
        return 1
    
    # Find all numeric folder names directly in reports/
    existing_numbers = []
    for folder in reports_dir.iterdir():
        if folder.is_dir() and folder.name.isdigit():
            existing_numbers.append(int(folder.name))
    
    if not existing_numbers:
        return 1
    
    # Return next number after the highest
    return max(existing_numbers) + 1


def validate_scan_id(scan_id: str) -> str:
    """
    Validate and sanitize scan ID to prevent filesystem issues.
    
    Rules:
    - Alphanumeric, dash, underscore only
    - Max 64 characters
    - No path traversal characters
    
    Raises ValueError if invalid.
    """
    import re
    
    if not scan_id:
        raise ValueError("Scan ID cannot be empty")
    
    # Remove dangerous characters
    if ".." in scan_id or "/" in scan_id or "\\" in scan_id:
        raise ValueError("Scan ID cannot contain path traversal characters (.. / \\)")
    
    # Must be alphanumeric with dashes/underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', scan_id):
        raise ValueError("Scan ID must contain only letters, numbers, dashes, and underscores")
    
    # Length limit
    if len(scan_id) > 64:
        raise ValueError("Scan ID must be 64 characters or less")
    
    return scan_id


def validate_repo_url(url: str) -> str:
    """
    Validate repository URL format.
    
    Accepts:
    - HTTPS: https://github.com/owner/repo
    - SSH: git@github.com:owner/repo.git
    
    Raises ValueError if invalid.
    """
    import re
    
    if not url:
        raise ValueError("Repository URL cannot be empty")
    
    # Check for valid URL patterns
    https_pattern = r'^https?://[\w\-.]+(:\d+)?/[\w\-./]+'
    ssh_pattern = r'^git@[\w\-.]+:[\w\-./]+'
    
    if not (re.match(https_pattern, url) or re.match(ssh_pattern, url)):
        raise ValueError(
            "Invalid repository URL format. Must be HTTPS (https://...) or SSH (git@...)"
        )
    
    return url.strip()


def validate_path(path: str, must_exist: bool = True) -> Path:
    """
    Validate and resolve file system path.
    
    Args:
        path: Path string to validate
        must_exist: If True, raises error if path doesn't exist
    
    Returns:
        Resolved Path object
    
    Raises:
        ValueError if path is invalid or doesn't exist (when must_exist=True)
    """
    if not path:
        raise ValueError("Path cannot be empty")
    
    try:
        p = Path(path).resolve()
    except Exception as e:
        raise ValueError(f"Invalid path '{path}': {e}")
    
    if must_exist and not p.exists():
        raise ValueError(f"Path does not exist: {p}")
    
    return p



def parse_args():
    p = argparse.ArgumentParser(
        prog="stacksqscanner",
        description="Generate SBOM (SPDX, CycloneDX, JSON) with vulnerability detection from OSV/CVE.",
    )

    # Source input (required - pick one)
    src_group = p.add_mutually_exclusive_group(required=False)
    src_group.add_argument("--repo", help="Git URL (https or ssh).")
    src_group.add_argument("--local", help="Local path to a folder to scan.")
    src_group.add_argument("--zip", help="Path to a .zip file to scan.")

    # Authentication (for private repos)
    p.add_argument("--token", help="Personal Access Token / App Password.", default=None)
    p.add_argument("--username", help="Username to pair with token for some providers/self-hosted.", default=None)
    
    # Output configuration
    p.add_argument("--reports-dir", default="reports", help="Base reports directory (default: reports).")
    p.add_argument("--temp-dir", default="temp", help="Temporary workspace directory (default: temp).")
    p.add_argument("--scan-id", help="Custom scan ID (optional, auto-generated if not provided).")
    
    # Optional flags
    p.add_argument("--keep-temp", action="store_true", help="Keep temp workspace after scan (for debugging).")
    p.add_argument("--max-workers", type=int, default=10, help="Concurrent workers for processing (default: 10).")

    return p.parse_args()



def prompt_repo_and_token(initial_repo: Optional[str], initial_token: Optional[str], initial_username: Optional[str]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Interactive helper to ask for repo + token if needed.
    Uses probe_repo_access() and verify_pat() from git_utils.
    Returns (repo, token_or_none, username_or_none).
    """
    repo = (initial_repo or "").strip()
    token = initial_token or None
    username = initial_username or None

    while not repo:
        repo = input("Enter repository URL (https or ssh): ").strip()

    print("-> Checking repository visibility...")
    try:
        status = probe_repo_access(repo, token=None)
    except Exception:
        status = "unknown_no_auth"

    if status == "public":
        print("[OK] Repo appears public (anonymous access possible).")
        return repo, None, None

    if status == "ok":
        print("[OK] Repo is accessible.")
        return repo, token, username

    if status in ("auth_required", "unknown_no_auth"):
        print("* This repository likely requires authentication.")
        attempts = 0
        while True:
            attempts += 1
            if not token:
                token = getpass("Enter token (PAT/App password) [hidden]: ").strip()
            # special-case Azure DevOps which sometimes requires username
            if not username and "dev.azure.com" in repo.lower():
                username = input("Azure DevOps often needs a username (usually your email). Enter username (or press Enter to skip): ").strip() or None
            print("-> Verifying token...")
            try:
                v = verify_pat(repo, token, username)
            except Exception:
                v = None
            if v == "ok":
                print("[OK] Token verified.")
                return repo, token, username
            print("[X] Auth failed. Re-enter credentials.")
            token = None
            username = None
            if attempts >= 5:
                raise SystemExit("Too many failed attempts. Exiting.")

    if status == "not_found":
        raise SystemExit("Repository not found or URL invalid.")
    if status == "network_error":
        raise SystemExit("Network error while probing repository.")

    print("! Could not determine visibility reliably; proceeding and may prompt for auth on clone.")
    return repo, token, username


def main():
    args = parse_args()

    # Validate inputs
    repo, token, username = args.repo, args.token, args.username
    
    # Interactive prompt for repo if not specified
    if not args.local and not args.zip:
        if not repo:
            repo = input("Enter Git repository URL (or press Enter to skip): ").strip() or None
        if repo:
            try:
                repo = validate_repo_url(repo)
                repo, token, username = prompt_repo_and_token(repo, token, username)
            except ValueError as e:
                raise SystemExit(f"Invalid repository URL: {e}")
    elif not (repo or args.local or args.zip):
        raise SystemExit("Please provide a source: --repo or --local or --zip (or run interactively).")

    # Validate paths if provided
    if args.local:
        try:
            validate_path(args.local, must_exist=True)
        except ValueError as e:
            raise SystemExit(f"Invalid local path: {e}")
    
    if args.zip:
        try:
            validate_path(args.zip, must_exist=True)
        except ValueError as e:
            raise SystemExit(f"Invalid zip path: {e}")

    # Validate and prepare directories
    try:
        reports_dir = validate_path(args.reports_dir, must_exist=False)
        temp_base = validate_path(args.temp_dir, must_exist=False)
    except ValueError as e:
        raise SystemExit(f"Invalid directory path: {e}")

    ensure_dir(reports_dir)
    ensure_dir(temp_base)

    # Note: scan_id is now generated by the orchestrator, not the CLI
    # The CLI just collects source information and lets orchestrator handle ID generation

    workspace = None
    
    try:
        # Determine source and source type
        if repo:
            source = repo
            source_type = "repo"
        elif args.local:
            source = args.local
            source_type = "local"
        elif args.zip:
            source = args.zip
            source_type = "zip"
        else:
            raise SystemExit("No source provided")
        
        # Derive project name from source
        project_name = "UNKNOWN"
        if repo:
            if repo.startswith("http"):
                project_name = repo.rstrip("/").split("/")[-1].replace(".git", "")
            else:
                project_name = Path(repo).name
        elif args.local:
            project_name = Path(args.local).name
        elif args.zip:
            project_name = Path(args.zip).stem
        
        # Initialize orchestrator
        orchestrator = ScanOrchestrator(
            reports_dir=str(reports_dir),
            temp_dir=str(temp_base)
        )
        
        print(f"\n{'='*60}")
        print(f"  StackSQScanner - SBOM Generation")
        print(f"{'='*60}")
        print(f"  Source: {source}")
        print(f"  Type: {source_type}")
        print(f"{'='*60}\n")
        
        # Run the complete scan pipeline using orchestrator
        # Orchestrator will auto-generate scan_id internally
        result: ScanResult = orchestrator.run_scan(
            source=source,
            source_type=source_type,
            token=token,
            username=username,
            project_name=project_name,
            cleanup_after=not args.keep_temp
        )
        
        # Now use the scan_id from the result
        scan_id = result.scan_id
        print(f"[INFO] Scan completed with ID: {scan_id}")
        
        if not result.success:
            print(f"\n[ERROR] Scan failed: {', '.join(result.errors)}")
            for warning in result.warnings:
                print(f"[WARN] {warning}")
            sys.exit(1)
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"  Scan ID: {result.scan_id}")
        print(f"  Duration: {result.duration_seconds:.2f} seconds")
        print(f"  Packages found: {len(result.packages)}")
        print(f"  Vulnerabilities: {result.vulnerabilities_count}")
        print(f"{'='*60}")
        
        # Print report paths
        print("\n  Reports Generated:")
        for format_name, path in result.reports.items():
            if path:
                print(f"    - {format_name}: {path}")
        
        if result.remediation_path:
            print(f"    - remediation: {result.remediation_path}")
        
        # Print warnings if any
        if result.warnings:
            print("\n  Warnings:")
            for warning in result.warnings:
                print(f"    - {warning}")
        
        print(f"\n{'='*60}\n")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

"""
PrismAIBOM Orchestrator — Web UI + background job runner.

Provides a browser-based interface for submitting scan jobs and monitoring
progress in real-time.  Calls the PrismAIBOM API endpoints in the same
FastAPI process via HTTP (localhost).
"""

import asyncio
import json
import os
import logging
import uuid
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Platform-specific imports for file locking
if sys.platform != "win32":
    import fcntl
else:
    fcntl = None

import httpx
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response

logger = logging.getLogger("orchestrator")

router = APIRouter(tags=["orchestrator"])

# ─── Configuration ──────────────────────────────────────────────────────────
APP_PORT = int(os.environ.get("APP_PORT", "7064"))
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", "/app/results"))

# ─── Shared file-backed job store (works across uvicorn workers) ────────────
MAX_CONCURRENT_JOBS = 5
_JOBS_FILE = "/app/temp/orchestrator_jobs.json"


class _SharedJobStore:
    """Process-safe job store backed by a JSON file on tmpfs."""

    def _atomic_op(self, fn):
        """Read-modify-write under an exclusive file lock."""
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            # Use fcntl on Unix systems, skip on Windows
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            
            raw = b""
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                raw += chunk
            data = json.loads(raw) if raw.strip() else {}
            result = fn(data)
            out = json.dumps(data).encode()
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, out)
            return result
        finally:
            # Unlock on Unix systems only
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def __init__(self, path: str = _JOBS_FILE):
        self._path = path

    def get(self, job_id: str) -> Optional[Dict]:
        def _op(data):
            return data.get(job_id)
        return self._atomic_op(_op)

    def put(self, job_id: str, job: Dict):
        def _op(data):
            data[job_id] = job
        self._atomic_op(_op)

    def delete(self, job_id: str):
        def _op(data):
            data.pop(job_id, None)
        self._atomic_op(_op)

    def all_values(self) -> List[Dict]:
        def _op(data):
            return list(data.values())
        return self._atomic_op(_op)

    def count_running(self) -> int:
        def _op(data):
            return sum(1 for j in data.values() if j.get("status") in ("running", "queued"))
        return self._atomic_op(_op)


_jobs = _SharedJobStore()

# ─── Endpoint sequence (mirrors pbom_executor.py) ──────────────────────────
ENDPOINT_SEQUENCE = [
    {"name": "Clean Resources",            "url": "/cleanresources",               "method": "POST", "status_code": 1},
    {"name": "Initialize Logging",         "url": "/initialize-log",               "method": "POST", "status_code": 1},
    # init step — replaced dynamically based on input type
    {"name": "Set Local Path",             "url": "/set-localpath",                "method": "POST", "status_code": 2, "init": True},
    # AIBOM
    {"name": "List Files",                 "url": "/aibom/files",                  "method": "GET",  "status_code": 3},
    {"name": "Extract Code Tokens",        "url": "/aibom/code-tokens",            "method": "GET",  "status_code": 4},
    {"name": "Analyze Packages",           "url": "/aibom/packages",               "method": "GET",  "status_code": 5},
    {"name": "Semgrep Imports Scan",       "url": "/aibom/semgrep-imports-scan",   "method": "GET",  "status_code": 6},
    {"name": "Resolve Packages",           "url": "/aibom/resolve-packages",       "method": "GET",  "status_code": 7},
    {"name": "Filtered Imports",           "url": "/aibom/filtered-imports",       "method": "GET",  "status_code": 8},
    {"name": "Dependency Graph",           "url": "/aibom/dependency-graph",       "method": "GET",  "status_code": 9},
    {"name": "LLM Validate",              "url": "/aibom/llm-validate",           "method": "GET",  "status_code": 10},
    {"name": "LLM Categorize",            "url": "/aibom/llm-categorize",         "method": "GET",  "status_code": 11},
    {"name": "AI Branch Trace",           "url": "/aibom/ai-branch-trace",        "method": "GET",  "status_code": 12},
    {"name": "AI Targeted Scan",          "url": "/aibom/ai-targeted-scan",       "method": "GET",  "status_code": 13},
    {"name": "Model Card Handler",        "url": "/aibom/model-card-handler",     "method": "GET",  "status_code": 14},
    {"name": "Model Deprecation Check",   "url": "/aibom/model-deprecation-check","method": "GET",  "status_code": 15},
    {"name": "AIBOM Connector",            "url": "/aibom/aibom-connector",         "method": "GET",  "status_code": 16},
    # SBOM
    {"name": "Start Scan",                "url": "/sbom/start-scan",              "method": "GET",  "status_code": 17},
    {"name": "Discover and Parse",        "url": "/sbom/discover-and-parse",      "method": "GET",  "status_code": 18},
    {"name": "Fetch Depsdev",             "url": "/sbom/fetch-depsdev",           "method": "GET",  "status_code": 19},
    {"name": "Registry Enrich",           "url": "/sbom/registry-enrich",         "method": "GET",  "status_code": 20},
    {"name": "Fetch OSV",                 "url": "/sbom/fetch-osv",              "method": "GET",  "status_code": 21},
    {"name": "Generate SBOM",             "url": "/sbom/generate-sbom",           "method": "GET",  "status_code": 22},
    # Final cleanup
    {"name": "Clean Resources",           "url": "/cleanresources",               "method": "POST", "status_code": 30},
]

ENDPOINTS_TO_STORE = {
    "/aibom/ai-branch-trace",
    "/aibom/model-card-handler",
    "/aibom/ai-targeted-scan",
    "/aibom/model-deprecation-check",
    "/aibom/aibom-connector",
    "/aibom/packages",
    "/aibom/llm-validate",
    "/aibom/semgrep-imports-scan",
    "/sbom/generate-sbom",
}


# ═══════════════════════════════════════════════════════════════════════════
# HTML UI (embedded for Nuitka compatibility — no external template files)
# ═══════════════════════════════════════════════════════════════════════════

_UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Prism Discovery</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg-base:#07090f;
  --bg-surface:rgba(15,20,35,.72);
  --bg-card:rgba(20,28,50,.55);
  --bg-card-hover:rgba(25,35,65,.65);
  --border:rgba(56,97,251,.12);
  --border-bright:rgba(56,97,251,.28);
  --accent:#3861fb;
  --accent-light:#5b8af5;
  --accent-glow:rgba(56,97,251,.25);
  --cyan:#06d6a0;
  --cyan-glow:rgba(6,214,160,.18);
  --red:#ff6b6b;
  --red-glow:rgba(255,107,107,.15);
  --amber:#fbbf24;
  --text-primary:#f0f2f8;
  --text-secondary:#8892b0;
  --text-muted:#5a6380;
  --radius:14px;
  --radius-sm:10px;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg-base);
     color:var(--text-primary);min-height:100vh;overflow-x:hidden;
     background-image:
       radial-gradient(ellipse 80% 50% at 50% -20%,rgba(56,97,251,.12),transparent),
       radial-gradient(ellipse 60% 40% at 80% 60%,rgba(6,214,160,.05),transparent);
     background-attachment:fixed}

/* ── Grid bg pattern ── */
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(56,97,251,.03) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(56,97,251,.03) 1px,transparent 1px);
  background-size:60px 60px;pointer-events:none;z-index:0}

.wrap{max-width:880px;margin:0 auto;padding:28px 20px;position:relative;z-index:1}

/* ── Topbar ── */
.topbar{display:flex;align-items:center;justify-content:space-between;
        padding:14px 0;margin-bottom:8px}
.topbar-brand{display:flex;align-items:center;gap:12px}
.logo-mark{height:38px;display:flex;align-items:center}
.logo-mark img{height:100%;width:auto;object-fit:contain}
.topbar-brand h1{font-size:1.15rem;font-weight:700;color:var(--text-primary);letter-spacing:-.01em}
.topbar-brand span{font-size:.72rem;color:var(--text-muted);font-weight:500;letter-spacing:.06em;text-transform:uppercase;display:block;margin-top:1px}
.topbar-status{display:flex;align-items:center;gap:8px;font-size:.78rem;color:var(--cyan);font-weight:500}
.topbar-status::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--cyan);
  box-shadow:0 0 8px var(--cyan);animation:pulse-dot 2s ease-in-out infinite}
@keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:.4}}

/* ── Hero ── */
.hero{text-align:center;padding:36px 0 28px}
.hero h2{font-size:2rem;font-weight:800;letter-spacing:-.03em;
          background:linear-gradient(135deg,#fff 0%,#a0b4f8 50%,var(--cyan) 100%);
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero p{color:var(--text-secondary);margin-top:8px;font-size:.95rem;max-width:520px;margin-left:auto;margin-right:auto;line-height:1.6}

/* ── Cards glass ── */
.card{background:var(--bg-card);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
      border:1px solid var(--border);border-radius:var(--radius);
      padding:28px;margin-bottom:22px;
      transition:border-color .25s,box-shadow .25s}
.card:hover{border-color:var(--border-bright);box-shadow:0 0 30px rgba(56,97,251,.06)}
.card-header{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.card-header .card-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:.95rem;background:linear-gradient(135deg,rgba(56,97,251,.18),rgba(6,214,160,.12));
  border:1px solid rgba(56,97,251,.15)}
.card-header h2{font-size:1rem;font-weight:600;color:var(--text-primary)}

/* ── Labels & inputs ── */
label{display:block;font-size:.8rem;color:var(--text-secondary);margin-bottom:6px;font-weight:500;letter-spacing:.02em}
input[type=text]{width:100%;padding:11px 16px;background:rgba(10,14,30,.65);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text-primary);font-size:.9rem;font-family:inherit;
  outline:none;transition:border .2s,box-shadow .2s}
input[type=text]:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
input[type=text]::placeholder{color:var(--text-muted)}

/* ── Source type toggle ── */
.src-toggle{display:inline-flex;background:rgba(10,14,30,.5);border:1px solid var(--border);
  border-radius:var(--radius-sm);overflow:hidden;margin-top:4px}
.src-toggle label{display:flex;align-items:center;gap:6px;padding:9px 20px;cursor:pointer;
  font-size:.85rem;font-weight:500;color:var(--text-secondary);transition:all .2s;margin-bottom:0;border:none}
.src-toggle input[type=radio]{display:none}
.src-toggle input[type=radio]:checked+span{color:var(--text-primary)}
.src-toggle label:has(input:checked){background:rgba(56,97,251,.15);color:var(--text-primary)}

.form-row{display:grid;grid-template-columns:1fr auto;gap:16px;margin-bottom:16px;align-items:end}
.form-group{margin-bottom:16px}

/* ── Buttons ── */
.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 30px;border:none;
     border-radius:var(--radius-sm);font-size:.9rem;font-weight:600;cursor:pointer;
     font-family:inherit;transition:all .2s;position:relative;overflow:hidden}
.btn-primary{background:linear-gradient(135deg,var(--accent),#2d4fdd);color:#fff;
  box-shadow:0 4px 16px var(--accent-glow)}
.btn-primary:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 24px rgba(56,97,251,.35)}
.btn-primary:active:not(:disabled){transform:translateY(0)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none!important}
.btn-sm{padding:7px 18px;font-size:.8rem}
.btn-ghost{background:transparent;color:var(--text-secondary);border:1px solid var(--border)}
.btn-ghost:hover{background:rgba(56,97,251,.08);border-color:var(--border-bright);color:var(--text-primary)}

.hidden{display:none!important}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:.73rem;
       font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.badge::before{content:'';width:6px;height:6px;border-radius:50%}
.badge.queued{background:rgba(90,99,128,.15);color:var(--text-muted)}
.badge.queued::before{background:var(--text-muted)}
.badge.running{background:rgba(56,97,251,.12);color:var(--accent-light)}
.badge.running::before{background:var(--accent-light);animation:pulse-dot 1.5s ease-in-out infinite}
.badge.completed{background:var(--cyan-glow);color:var(--cyan)}
.badge.completed::before{background:var(--cyan)}
.badge.failed{background:var(--red-glow);color:var(--red)}
.badge.failed::before{background:var(--red)}

/* ── Status bar & progress ── */
.status-bar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.status-bar .meta{font-size:.8rem;color:var(--text-muted);font-weight:500}
.progress-track{width:100%;height:4px;background:rgba(56,97,251,.08);border-radius:4px;margin-bottom:22px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--cyan));border-radius:4px;
               transition:width .5s cubic-bezier(.4,0,.2,1);width:0;
               box-shadow:0 0 12px var(--accent-glow)}

/* ── Steps ── */
.step{display:flex;align-items:center;gap:10px;padding:8px 0;font-size:.85rem;
      color:var(--text-muted);border-bottom:1px solid rgba(56,97,251,.05)}
.step:last-child{border-bottom:none}
.step-icon{width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;
           font-size:.8rem;flex-shrink:0;background:rgba(90,99,128,.1);border:1px solid transparent}
.step.done{color:var(--cyan)}
.step.done .step-icon{background:var(--cyan-glow);border-color:rgba(6,214,160,.2);color:var(--cyan)}
.step.active{color:var(--accent-light);font-weight:600}
.step.active .step-icon{background:rgba(56,97,251,.12);border-color:rgba(56,97,251,.25);color:var(--accent-light);
  animation:pulse-step 2s ease-in-out infinite}
@keyframes pulse-step{0%,100%{box-shadow:0 0 0 0 var(--accent-glow)}50%{box-shadow:0 0 0 6px transparent}}
.step.error{color:var(--red)}
.step.error .step-icon{background:var(--red-glow);border-color:rgba(255,107,107,.2);color:var(--red)}
.step .step-dur{color:var(--text-muted);font-size:.75rem;font-weight:400;margin-left:auto}

/* ── Result boxes ── */
.result-box{margin-top:18px;padding:16px 20px;border-radius:var(--radius-sm);
            font-size:.88rem;word-break:break-all;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.result-box.success-box{background:rgba(6,214,160,.08);border:1px solid rgba(6,214,160,.18);color:var(--cyan)}
.result-box.error-box{background:var(--red-glow);border:1px solid rgba(255,107,107,.2);color:var(--red)}
.result-box .dl-btn{margin-left:auto;padding:7px 18px;background:linear-gradient(135deg,var(--accent),#2d4fdd);
  color:#fff;border-radius:8px;text-decoration:none;font-size:.82rem;font-weight:600;
  box-shadow:0 2px 10px var(--accent-glow);transition:all .2s;white-space:nowrap}
.result-box .dl-btn:hover{transform:translateY(-1px);box-shadow:0 4px 16px rgba(56,97,251,.35)}

/* ── History ── */
.history-item{display:flex;align-items:center;justify-content:space-between;padding:12px 0;
              border-bottom:1px solid rgba(56,97,251,.05);font-size:.85rem;gap:12px}
.history-item:last-child{border-bottom:none}
.history-item .left{display:flex;align-items:center;gap:10px;min-width:0}
.history-item .left span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.history-item .right{color:var(--text-muted);font-size:.75rem;font-family:'SF Mono',monospace;white-space:nowrap}
.history-item .dl-sm{padding:4px 12px;background:linear-gradient(135deg,var(--accent),#2d4fdd);
  color:#fff;border-radius:6px;text-decoration:none;font-size:.72rem;font-weight:600;
  transition:all .2s;white-space:nowrap}
.history-item .dl-sm:hover{box-shadow:0 2px 10px var(--accent-glow)}
.empty-state{text-align:center;color:var(--text-muted);padding:28px 0;font-size:.88rem}

/* ── Browse modal ── */
.modal-overlay{position:fixed;inset:0;background:rgba(7,9,15,.75);backdrop-filter:blur(8px);
  z-index:1000;display:flex;align-items:center;justify-content:center}
.modal{background:rgba(15,20,38,.95);backdrop-filter:blur(24px);border:1px solid var(--border-bright);
  border-radius:var(--radius);width:580px;max-width:95vw;max-height:80vh;display:flex;flex-direction:column;
  box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 40px var(--accent-glow)}
.modal-header{display:flex;align-items:center;justify-content:space-between;padding:18px 24px;
  border-bottom:1px solid var(--border)}
.modal-header h3{font-size:1rem;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:8px}
.modal-close{background:none;border:none;color:var(--text-muted);font-size:1.4rem;cursor:pointer;padding:0 4px;
  transition:color .15s}
.modal-close:hover{color:var(--text-primary)}
.modal-breadcrumb{padding:10px 24px;font-size:.8rem;color:var(--text-muted);border-bottom:1px solid rgba(56,97,251,.05);
  display:flex;align-items:center;gap:4px;flex-wrap:wrap}
.modal-breadcrumb span{cursor:pointer;color:var(--accent-light);transition:color .15s}
.modal-breadcrumb span:hover{color:#fff;text-decoration:underline}
.modal-body{flex:1;overflow-y:auto;padding:10px 16px}
.modal-body::-webkit-scrollbar{width:6px}
.modal-body::-webkit-scrollbar-track{background:transparent}
.modal-body::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.browse-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;cursor:pointer;
  font-size:.88rem;color:var(--text-secondary);transition:all .15s}
.browse-item:hover{background:rgba(56,97,251,.08);color:var(--text-primary)}
.browse-item.selected{background:rgba(56,97,251,.15);color:var(--accent-light);border:1px solid rgba(56,97,251,.2)}
.browse-item .icon{font-size:1.05rem;width:22px;text-align:center;flex-shrink:0}
.browse-item .name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.browse-item.file-item{color:var(--text-muted);cursor:default;opacity:.5}
.browse-item.file-item:hover{background:transparent;color:var(--text-muted)}
.modal-footer{padding:16px 24px;border-top:1px solid var(--border);display:flex;align-items:center;
  justify-content:space-between;gap:12px}
.modal-footer .selected-path{flex:1;font-size:.8rem;color:var(--text-muted);overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;font-family:'SF Mono',monospace}

.input-with-btn{display:flex;gap:8px;align-items:center}
.input-with-btn input{flex:1}
.btn-browse{padding:11px 20px;background:rgba(56,97,251,.1);color:var(--accent-light);
  border:1px solid var(--border-bright);border-radius:var(--radius-sm);
  font-size:.88rem;font-weight:500;cursor:pointer;white-space:nowrap;font-family:inherit;
  transition:all .2s;display:flex;align-items:center;gap:6px}
.btn-browse:hover{background:rgba(56,97,251,.18);border-color:var(--accent);color:#fff}

/* ── Footer ── */
.footer{text-align:center;padding:32px 0 16px;color:var(--text-muted);font-size:.75rem}
.footer a{color:var(--accent-light);text-decoration:none}

/* ── Animations ── */
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.card{animation:fadeIn .4s ease-out both}
.card:nth-child(2){animation-delay:.1s}
.card:nth-child(3){animation-delay:.2s}
</style>
</head>
<body>
<div class="wrap">

  <!-- ── Topbar ── -->
  <div class="topbar">
    <div class="topbar-brand">
      <div class="logo-mark"><img src="https://prism.sisa.ai/assets/images/logo.png" alt="Prism"></div>
      <div>
        <h1>Prism Discovery</h1>
        <span>AI &amp; Software BOM Platform</span>
      </div>
    </div>
    <div class="topbar-status">System Online</div>
  </div>

  <!-- ── Hero ── -->
  <div class="hero">
    <h2>Secure AI Discovery<br>From Pilot to Production</h2>
    <p>Comprehensive AI &amp; Software Bill of Materials analysis with real-time scanning, dependency mapping, and vulnerability assessment.</p>
  </div>

  <!-- ── Scan Form ── -->
  <div class="card" id="formCard">
    <div class="card-header">
      <div class="card-icon">&#9881;</div>
      <h2>New Scan</h2>
    </div>

    <div class="form-group">
      <label>Source Type</label>
      <div class="src-toggle">
        <label><input type="radio" name="srcType" value="local" checked onchange="switchSource()"><span>&#128196; Local Path</span></label>
        <label><input type="radio" name="srcType" value="url" onchange="switchSource()"><span>&#128279; GitHub URL</span></label>
      </div>
    </div>

    <div class="form-group" id="localGroup">
      <label for="localPath">Repository Path on Server</label>
      <div class="input-with-btn">
        <input type="text" id="localPath" placeholder="/data/my-repo  or  /home/user/project">
        <button type="button" class="btn-browse" onclick="openBrowser()">&#128193; Browse</button>
      </div>
      <span style="font-size:.73rem;color:var(--text-muted);margin-top:5px;display:block">
        Absolute path to the repository directory on the host machine
      </span>
    </div>

    <div class="form-group hidden" id="urlGroup">
      <label for="repoUrl">GitHub Repository URL</label>
      <input type="text" id="repoUrl" placeholder="https://github.com/org/repo">
    </div>
    <div class="form-group hidden" id="patGroup">
      <label for="patInput">Personal Access Token <span style="color:var(--text-muted)">(optional, for private repos)</span></label>
      <input type="text" id="patInput" placeholder="ghp_xxxx / glpat-xxxx">
    </div>

    <div class="form-row">
      <div>
        <label for="scanId">Scan ID</label>
        <input type="text" id="scanId" placeholder="e.g. scan-001">
      </div>
      <button class="btn btn-primary" id="startBtn" onclick="startScan()">
        &#9654; Start Scan
      </button>
    </div>
    <div id="formError" class="hidden" style="color:var(--red);font-size:.83rem;margin-top:4px"></div>
  </div>

  <!-- ── Progress ── -->
  <div class="card hidden" id="progressCard">
    <div class="card-header">
      <div class="card-icon">&#9201;</div>
      <h2>Scan Progress</h2>
    </div>
    <div class="status-bar">
      <div><span id="statusBadge" class="badge queued">Queued</span></div>
      <div class="meta" id="jobMeta"></div>
    </div>
    <div class="progress-track"><div class="progress-fill" id="progFill"></div></div>
    <div id="stepsList"></div>
    <div id="resultSection" class="hidden"></div>
  </div>

  <!-- ── History ── -->
  <div class="card">
    <div class="card-header">
      <div class="card-icon">&#128203;</div>
      <h2>Recent Scans</h2>
    </div>
    <div id="historyList"><div class="empty-state">No scans yet — start your first scan above</div></div>
  </div>

  <div class="footer">
    Prism Discovery &mdash; AI &amp; Software Bill of Materials Platform
  </div>
</div>

<!-- Folder browser modal — must be outside .card to avoid backdrop-filter breaking position:fixed -->
<div id="browseModal" class="modal-overlay hidden" onclick="if(event.target===this)closeBrowser()">
  <div class="modal">
    <div class="modal-header">
      <h3>&#128193; Select Folder</h3>
      <button class="modal-close" onclick="closeBrowser()">&times;</button>
    </div>
    <div class="modal-breadcrumb" id="breadcrumb"></div>
    <div class="modal-body" id="browseList"></div>
    <div class="modal-footer">
      <div class="selected-path" id="selectedPath">No folder selected</div>
      <button class="btn btn-ghost btn-sm" onclick="closeBrowser()">Cancel</button>
      <button class="btn btn-primary btn-sm" id="selectBtn" onclick="confirmSelect()" disabled>Select</button>
    </div>
  </div>
</div>

<script>
let currentJobId=null, pollTimer=null;

function $(id){return document.getElementById(id)}
function show(el){el.classList.remove('hidden')}
function hide(el){el.classList.add('hidden')}
function getSourceType(){return document.querySelector('input[name="srcType"]:checked').value}
function resetForm(){
  $('startBtn').disabled=false;$('startBtn').innerHTML='&#9654; Start Scan';
  hide($('formError'));
}

function switchSource(){
  const t=getSourceType();
  if(t==='local'){show($('localGroup'));hide($('urlGroup'));hide($('patGroup'))}
  else{hide($('localGroup'));show($('urlGroup'));show($('patGroup'))}
  hide($('formError'));
}

/* ── folder browser ── */
let _browsePath='/', _selectedDir=null;
function openBrowser(){
  _selectedDir=null;$('selectBtn').disabled=true;
  $('selectedPath').textContent='No folder selected';show($('browseModal'));
  const cur=$('localPath').value.trim();
  loadDir(cur&&cur.startsWith('/')?cur:'/');
}
function closeBrowser(){hide($('browseModal'))}
async function loadDir(path){
  _browsePath=path;_selectedDir=path;$('selectBtn').disabled=false;
  $('selectedPath').textContent=path;
  $('browseList').innerHTML='<div class="empty-state">Loading...</div>';
  try{
    const res=await fetch('/api/browse?path='+encodeURIComponent(path));
    if(!res.ok){const e=await res.json();$('browseList').innerHTML='<div class="empty-state" style="color:var(--red)">'+e.detail+'</div>';return}
    const data=await res.json();_browsePath=data.path;_selectedDir=data.path;
    $('selectedPath').textContent=data.path;renderBreadcrumb(data.path);renderEntries(data);
  }catch(e){$('browseList').innerHTML='<div class="empty-state" style="color:var(--red)">Failed to load directory</div>'}
}
function renderBreadcrumb(p){
  const parts=p.split('/').filter(Boolean);let html='<span onclick="loadDir(\'/\')">/ root</span>';let built='';
  for(const part of parts){built+='/'+part;const safe=built.replace(/'/g,"\\'");
    html+=' / <span onclick="loadDir(\''+safe+'\')">'+part+'</span>'}
  $('breadcrumb').innerHTML=html;
}
function renderEntries(data){
  const dirs=data.entries.filter(e=>e.type==='dir'),files=data.entries.filter(e=>e.type==='file');
  if(!dirs.length&&!files.length){$('browseList').innerHTML='<div class="empty-state">Empty directory</div>';return}
  let html='';
  if(data.parent!==null){const safe=data.parent.replace(/'/g,"\\'");
    html+='<div class="browse-item" ondblclick="loadDir(\''+safe+'\')"><span class="icon">&#11168;</span><span class="name">..</span></div>'}
  for(const d of dirs){const full=(_browsePath==='/'?'':_browsePath)+'/'+d.name;const safe=full.replace(/'/g,"\\'");
    html+='<div class="browse-item" onclick="selectDir(\''+safe+'\',this)" ondblclick="loadDir(\''+safe+'\')"><span class="icon">&#128193;</span><span class="name">'+d.name+'</span></div>'}
  for(const f of files.slice(0,50)){html+='<div class="browse-item file-item"><span class="icon">&#128196;</span><span class="name">'+f.name+'</span></div>'}
  if(files.length>50) html+='<div class="empty-state">...and '+(files.length-50)+' more files</div>';
  $('browseList').innerHTML=html;
}
function selectDir(path,el){
  _selectedDir=path;$('selectedPath').textContent=path;$('selectBtn').disabled=false;
  document.querySelectorAll('#browseList .browse-item.selected').forEach(e=>e.classList.remove('selected'));
  el.classList.add('selected');
}
function confirmSelect(){if(_selectedDir)$('localPath').value=_selectedDir;closeBrowser()}

/* ── start scan ── */
async function startScan(){
  const srcType=getSourceType(),scanId=$('scanId').value.trim();let repoPath,pat=null;
  if(srcType==='local'){
    repoPath=$('localPath').value.trim();
    if(!repoPath){show($('formError'));$('formError').textContent='Please enter the local repository path';return}
    if(!repoPath.startsWith('/')){show($('formError'));$('formError').textContent='Local path must be an absolute path (starting with /)';return}
  }else{
    repoPath=$('repoUrl').value.trim();pat=$('patInput').value.trim()||null;
    if(!repoPath){show($('formError'));$('formError').textContent='Please enter the GitHub repository URL';return}
    if(!/^https?:\/\//i.test(repoPath)){show($('formError'));$('formError').textContent='URL must start with https://';return}
  }
  if(!scanId){show($('formError'));$('formError').textContent='Please enter a Scan ID';return}
  hide($('formError'));$('startBtn').disabled=true;$('startBtn').innerHTML='&#9203; Initializing\u2026';
  try{
    const res=await fetch('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({repo_path:repoPath,scan_id:scanId,pat:pat||null})});
    if(!res.ok){const e=await res.json();throw new Error(e.detail||'Failed to create job')}
    const data=await res.json();currentJobId=data.job_id;
    show($('progressCard'));$('jobMeta').textContent='Job: '+currentJobId;
    $('stepsList').innerHTML='';hide($('resultSection'));
    if(pollTimer)clearInterval(pollTimer);
    pollTimer=setInterval(pollStatus,3000);pollStatus();
    resetForm();
  }catch(err){show($('formError'));$('formError').textContent=err.message;
    resetForm();
  }
}

/* ── poll ── */
async function pollStatus(){
  if(!currentJobId)return;
  try{
    const res=await fetch('/api/jobs/'+currentJobId);
    if(res.status===404){clearInterval(pollTimer);show($('resultSection'));
      $('resultSection').innerHTML='<div class="result-box error-box">&#10060; Scan not found</div>';
      refreshHistory();return}
    const job=await res.json();renderJob(job);
    if(job.status==='completed'||job.status==='failed'){clearInterval(pollTimer);refreshHistory()}
  }catch(e){}
}

/* ── render ── */
function renderJob(job){
  const badge=$('statusBadge');badge.textContent=job.status;badge.className='badge '+job.status;
  const pct=job.total_steps>0?Math.round(job.steps_completed/job.total_steps*100):0;
  $('progFill').style.width=pct+'%';
  $('jobMeta').textContent='Job: '+job.job_id+'  \u00b7  '+pct+'%';
  let html='';
  for(const s of job.steps){
    let icon='\u25cb',cls='';
    if(s.status==='completed'){icon='\u2713';cls='done'}
    else if(s.status==='running'){icon='\u21bb';cls='active'}
    else if(s.status==='failed'){icon='\u2717';cls='error'}
    let dur=s.duration?'<span class="step-dur">'+s.duration.toFixed(1)+'s</span>':'';
    html+='<div class="step '+cls+'"><span class="step-icon">'+icon+'</span><span>'+s.name+'</span>'+dur+'</div>';
  }
  $('stepsList').innerHTML=html;
  if(job.status==='completed'&&job.result_file){show($('resultSection'));
    $('resultSection').innerHTML='<div class="result-box success-box">&#9989; <strong>'+job.result_file+'</strong>'
      +'<a class="dl-btn" href="/api/jobs/'+job.job_id+'/download" download>\u2b07 Download Result</a></div>'}
  if(job.status==='failed'&&job.error){show($('resultSection'));
    $('resultSection').innerHTML='<div class="result-box error-box">&#10060; '+job.error+'</div>'}
}

/* ── track a job from history ── */
function trackJob(jobId){
  currentJobId=jobId;
  if(pollTimer)clearInterval(pollTimer);
  show($('progressCard'));$('jobMeta').textContent='Job: '+jobId;
  $('stepsList').innerHTML='';hide($('resultSection'));
  pollTimer=setInterval(pollStatus,3000);pollStatus();
  $('progressCard').scrollIntoView({behavior:'smooth'});
}

/* ── history ── */
async function refreshHistory(){
  try{
    const res=await fetch('/api/jobs');const jobs=await res.json();
    if(!jobs.length){$('historyList').innerHTML='<div class="empty-state">No scans yet \u2014 start your first scan above</div>';return}
    let html='';
    for(const j of jobs.slice(-20).reverse()){
      const badge='<span class="badge '+j.status+'">'+j.status+'</span>';
      let dl=(j.status==='completed'&&j.result_file)?' <a class="dl-sm" href="/api/jobs/'+j.job_id+'/download" download>\u2b07 Download</a>':'';
      let track=(j.status==='running'||j.status==='queued')?' <a class="dl-sm" style="background:linear-gradient(135deg,var(--accent),#2d4fdd);cursor:pointer" onclick="trackJob(\''+j.job_id+'\')">&circlearrowright; Track</a>':'';
      let view=(j.status==='completed'||j.status==='failed')?' <a class="dl-sm" style="background:rgba(90,99,128,.3);cursor:pointer" onclick="trackJob(\''+j.job_id+'\')">&varr; View</a>':'';
      html+='<div class="history-item"><div class="left">'+badge+' <span>'+j.scan_id+'</span>'+dl+track+view+'</div>'
        +'<div class="right">'+j.job_id+'</div></div>'}
    $('historyList').innerHTML=html;
  }catch(e){}
}
refreshHistory();setInterval(refreshHistory,3000);
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════
# API routes
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def ui_home():
    """Serve the scanner UI."""
    return HTMLResponse(content=_UI_HTML)


# Host filesystem mount point inside the container
HOSTFS = os.environ.get("HOSTFS_MOUNT", "/hostfs")

def _to_container_path(host_path: str) -> str:
    """Translate a host path to the container-internal path via /hostfs mount."""
    # Always try the hostfs mount first so we browse the host filesystem
    candidate = os.path.join(HOSTFS, host_path.lstrip("/"))
    if os.path.isdir(candidate):
        return candidate
    # Fall back to container-local path only if hostfs doesn't have it
    if os.path.isdir(host_path):
        return host_path
    return candidate

def _to_host_path(container_path: str) -> str:
    """Strip the /hostfs prefix so the user sees the real host path."""
    if container_path.startswith(HOSTFS + "/"):
        return container_path[len(HOSTFS):]
    if container_path == HOSTFS:
        return "/"
    return container_path


@router.get("/api/browse")
async def browse_directory(request: Request):
    """List directories at a given server path for the folder picker UI."""
    path = request.query_params.get("path", "/").strip()
    if not path:
        path = "/"

    # Translate host path to container path (via /hostfs mount)
    container_path = _to_container_path(path)
    if not os.path.isdir(container_path):
        raise HTTPException(400, f"Not a directory: {path}")

    entries = []
    try:
        for name in sorted(os.listdir(container_path)):
            if name.startswith("."):
                continue
            full = os.path.join(container_path, name)
            if os.path.isdir(full):
                entries.append({"name": name, "type": "dir"})
            else:
                entries.append({"name": name, "type": "file"})
    except PermissionError:
        raise HTTPException(403, f"Permission denied: {path}")

    host_path = _to_host_path(container_path)
    parent_host = os.path.dirname(host_path) if host_path != "/" else None

    return {
        "path": host_path,
        "parent": parent_host,
        "entries": entries,
    }


@router.post("/api/jobs")
async def create_job(request: Request):
    """Create a new scan job and begin processing in the background."""
    global _running_count
    body = await request.json()

    repo_path = (body.get("repo_path") or "").strip()
    scan_id = (body.get("scan_id") or "").strip()
    pat = (body.get("pat") or "").strip() or None

    if not repo_path or not scan_id:
        raise HTTPException(400, "repo_path and scan_id are required")
    if _jobs.count_running() >= MAX_CONCURRENT_JOBS:
        raise HTTPException(429, f"Too many concurrent jobs (max {MAX_CONCURRENT_JOBS})")

    job_id = f"{scan_id}_{uuid.uuid4().hex[:8]}"

    # Build the step-tracking list from ENDPOINT_SEQUENCE
    steps: List[Dict[str, Any]] = []
    for ep in ENDPOINT_SEQUENCE:
        steps.append({
            "name": ep["name"],
            "url": ep["url"],
            "status": "pending",
            "duration": None,
        })

    job: Dict[str, Any] = {
        "job_id": job_id,
        "scan_id": scan_id,
        "repo_path": repo_path,
        "pat": pat,
        "status": "queued",
        "steps_completed": 0,
        "total_steps": len(ENDPOINT_SEQUENCE),
        "steps": steps,
        "result_file": None,
        "error": None,
        "created_at": datetime.now().isoformat(),
    }
    _jobs.put(job_id, job)

    asyncio.create_task(_run_job(job_id))
    return {"job_id": job_id}


@router.get("/api/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Return current state of a job (for UI polling)."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    # Don't leak the PAT
    safe = {k: v for k, v in job.items() if k != "pat"}
    return JSONResponse(content=safe)


@router.get("/api/jobs/{job_id}/download")
async def download_result(job_id: str):
    """Download the result JSON file, then delete it and clear job data."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    if job["status"] != "completed" or not job.get("result_file"):
        raise HTTPException(400, "Result not available yet")
    result_path = Path(job["result_file"])
    if not result_path.is_file():
        raise HTTPException(404, "Result file not found on disk")

    # Read file content into memory before deleting
    content = result_path.read_bytes()
    filename = result_path.name

    # Delete result file from disk
    try:
        result_path.unlink()
    except OSError:
        pass

    # Clear job data
    _jobs.delete(job_id)

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/jobs")
async def list_jobs():
    """Return summary list (most-recent last)."""
    out = []
    for j in _jobs.all_values():
        out.append({
            "job_id": j["job_id"],
            "scan_id": j["scan_id"],
            "status": j["status"],
            "created_at": j["created_at"],
            "result_file": j.get("result_file"),
        })
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Background job processor
# ═══════════════════════════════════════════════════════════════════════════

async def _run_job(job_id: str):
    """Execute all endpoints sequentially for a job.

    The actual HTTP calls run in a thread so the async event-loop stays
    free for UI / polling requests.
    """
    job = _jobs.get(job_id)
    job["status"] = "running"
    _jobs.put(job_id, job)

    try:
        await asyncio.to_thread(_run_job_sync, job_id, job)
    except Exception as exc:
        logger.error(f"[{job_id}] Job failed: {exc}")
        job["status"] = "failed"
        job["error"] = str(exc)
        _jobs.put(job_id, job)


def _run_job_sync(job_id: str, job: Dict[str, Any]):
    """Synchronous job runner — executes inside a worker thread."""
    session_token: Optional[str] = None

    base_url = f"http://127.0.0.1:{APP_PORT}"
    repo_path = job["repo_path"]
    scan_id = job["scan_id"]
    pat = job.get("pat")
    is_url = repo_path.startswith("http://") or repo_path.startswith("https://") or repo_path.startswith("git@")

    # Build endpoint list — swap init step depending on input type
    endpoints = list(ENDPOINT_SEQUENCE)
    if is_url:
        for i, ep in enumerate(endpoints):
            if ep.get("init"):
                endpoints[i] = {
                    "name": "Set Repository",
                    "url": "/set-repository",
                    "method": "POST",
                    "status_code": 2,
                }
                job["steps"][i]["name"] = "Set Repository"
                job["steps"][i]["url"] = "/set-repository"
                break

    # Collected responses for result file
    responses: Dict[str, Any] = {}

    with httpx.Client(timeout=httpx.Timeout(600, connect=30)) as client:
        for idx, ep in enumerate(endpoints):
            step = job["steps"][idx]
            step["status"] = "running"
            _jobs.put(job_id, job)

            url = ep["url"]
            method = ep.get("method", "GET")
            t0 = datetime.now()

            try:
                result = _call_endpoint_sync(
                    client, base_url, url, method,
                    ep=ep, scan_id=scan_id, repo_path=repo_path,
                    pat=pat, session_token=session_token, is_url=is_url,
                )
            except Exception as exc:
                step["status"] = "failed"
                step["duration"] = (datetime.now() - t0).total_seconds()
                _jobs.put(job_id, job)
                raise RuntimeError(f"{ep['name']}: {exc}") from exc

            duration = (datetime.now() - t0).total_seconds()
            step["duration"] = duration
            http_status = result.get("status_code", 500)

            # Extract session token from init response
            if url in ("/set-repository", "/set-localpath") and http_status < 400:
                resp_body = result.get("body", {})
                if isinstance(resp_body, dict):
                    session_token = resp_body.get("session_token")

            # Store selected responses
            if url in ENDPOINTS_TO_STORE:
                key = url.strip("/").replace("/", "_")
                responses[key] = {
                    "response": result.get("body"),
                    "status_code": http_status,
                    "timestamp": datetime.now().isoformat(),
                }

            if http_status >= 400:
                step["status"] = "failed"
                _jobs.put(job_id, job)
                # Attempt cleanup
                try:
                    client.post(f"{base_url}/cleanresources", timeout=30)
                except Exception:
                    pass
                raise RuntimeError(
                    f"{ep['name']} failed (HTTP {http_status})"
                )

            step["status"] = "completed"
            job["steps_completed"] = idx + 1
            _jobs.put(job_id, job)

    # ── Success: write result file ──────────────────────────────────
    result_data = {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": 1,
        "responses": responses,
        "Scanstarttime": job["created_at"],
        "endtime": datetime.now().isoformat(),
        "last_updated": datetime.now().isoformat(),
    }

    result_path = _save_result(result_data, scan_id, repo_path, is_url)
    job["result_file"] = str(result_path)
    job["status"] = "completed"
    _jobs.put(job_id, job)


# ═══════════════════════════════════════════════════════════════════════════
# Endpoint caller
# ═══════════════════════════════════════════════════════════════════════════

def _call_endpoint_sync(
    client: httpx.Client,
    base_url: str,
    url: str,
    method: str,
    *,
    ep: dict,
    scan_id: str,
    repo_path: str,
    pat: Optional[str],
    session_token: Optional[str],
    is_url: bool,
) -> Dict[str, Any]:
    """Make a single HTTP call to the PrismAIBOM service (sync — runs in thread)."""
    full_url = f"{base_url}{url}"
    headers: Dict[str, str] = {"Content-Type": "application/json"}

    no_token = {"/cleanresources", "/set-repository", "/set-localpath", "/initialize-log"}
    if session_token and url not in no_token:
        headers["session-token"] = session_token

    # ── /set-localpath — JSON body with local filesystem path ────────────
    if ep.get("init") and url == "/set-localpath":
        payload = {"local_path": repo_path}
        resp = client.post(full_url, json=payload, headers=headers, timeout=300)
        body = _safe_json(resp)
        return {"status_code": resp.status_code, "body": body}

    # ── /set-repository — JSON body ─────────────────────────────────────
    if url == "/set-repository":
        payload = {"repo_url": repo_path}
        if pat:
            payload["pat"] = pat
        resp = client.post(full_url, json=payload, headers=headers, timeout=300)
        return {"status_code": resp.status_code, "body": _safe_json(resp)}

    # ── /initialize-log — JSON body ─────────────────────────────────────
    if url == "/initialize-log":
        resp = client.post(full_url, json={"scan_id": scan_id}, headers=headers, timeout=60)
        return {"status_code": resp.status_code, "body": _safe_json(resp)}

    # ── /cleanresources — no body ───────────────────────────────────────
    if url == "/cleanresources":
        resp = client.post(full_url, timeout=120)
        return {"status_code": resp.status_code, "body": _safe_json(resp)}

    # ── GET endpoints ───────────────────────────────────────────────────
    if method == "GET":
        resp = client.get(full_url, headers=headers, timeout=600)
        return {"status_code": resp.status_code, "body": _safe_json(resp)}

    # Fallback POST
    resp = client.post(full_url, headers=headers, timeout=300)
    return {"status_code": resp.status_code, "body": _safe_json(resp)}


def _safe_json(resp: httpx.Response) -> Any:
    ct = resp.headers.get("content-type", "")
    if "json" in ct:
        try:
            return resp.json()
        except Exception:
            pass
    return resp.text


# ═══════════════════════════════════════════════════════════════════════════
# Result file writer
# ═══════════════════════════════════════════════════════════════════════════

def _save_result(data: dict, scan_id: str, repo_path: str, is_url: bool) -> Path:
    """Write the result JSON to disk and return its path."""
    filename = f"prism_discovery_result_{scan_id}.json"

    if not is_url:
        dest_dir = Path(repo_path)
        if dest_dir.is_dir():
            out = dest_dir / filename
            _atomic_write(out, data)
            return out

    # Fallback: central results directory
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / filename
    _atomic_write(out, data)
    return out


def _atomic_write(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)

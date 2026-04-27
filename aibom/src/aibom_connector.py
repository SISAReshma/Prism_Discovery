"""
AIBOM Connector — Pluggable Multi-Source AI BOM Generator
==========================================================
Aggregates model metadata from multiple registries via a pluggable
connector architecture, assembles CycloneDX-ready AI BOM components,
absorbs deprecation checking, and includes agentic framework assets.

Each data source implements ``BaseModelConnector`` and is registered
in the ``ConnectorRegistry``.  Resolution follows a waterfall strategy
with heuristic routing: connectors are tried in priority order, and
the first one that returns data wins.

New sources are added by subclassing ``BaseModelConnector`` and calling
``connector_registry.register(MyConnector())``.

Sources implemented (v1):
    - ModelCacheConnector       (local O(1) cache)
    - HuggingFaceConnector      (HF Hub REST API)
    - ReplicateConnector        (Replicate REST API)
    - AzureAICatalogConnector   (Azure AI Foundry catalog)
    - TFHubConnector            (TensorFlow Hub)
    - ONNXModelZooConnector     (ONNX Model Zoo / GitHub)
    - GitRepoConnector          (session scan data)

Stubs (interface defined, pending auth / integration):
    - PyTorchHubConnector, KaggleConnector,
      MLflowConnector, SageMakerConnector, AzureMLConnector,
      VertexAIConnector, WandBConnector, OCIRegistryConnector
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

import certifi
import requests

from aibom.config import (
    DEPRECATION_CACHE_DIR,
    DEPRECATION_MAX_CHAIN_DEPTH,
    DEPRECATION_PROVIDER_PATTERNS,
    DEPRECATION_SEVERITY_THRESHOLDS,
    DEPRECATED_STATUSES,
    HUGGINGFACE_API_BASE,
    HUGGINGFACE_RAW_BASE,
    AZURE_AI_CATALOG_API,
    MODEL_CACHE_DIR,
    MODEL_CACHE_EXPIRY_DAYS,
    MODEL_CARD_TIMEOUT,
    MODEL_PROVIDER_PREFIXES,
    PROVIDER_CANONICAL_MAP,
    PROVIDER_HF_ORG_FALLBACK,
    PROVIDER_API_CONFIG,
    README_FETCH_TIMEOUT,
    UPSTREAM_MODEL_CARD_SOURCES,
)
from aibom.src.model_suffix_handler import (
    extract_suffix_info,
    parse_suffix,
    strip_model_name_incrementally,
)
from core.log_sanitizer import sanitize_sensitive

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CONNECTOR API URLS (configurable via env vars)
# ═══════════════════════════════════════════════════════════════════════════════

REPLICATE_API_BASE: str = os.environ.get(
    "REPLICATE_API_BASE", "https://api.replicate.com/v1"
)
TFHUB_API_BASE: str = os.environ.get(
    "TFHUB_API_BASE", "https://tfhub.dev/api/v1"
)
ONNX_ZOO_RAW_BASE: str = (
    "https://raw.githubusercontent.com/onnx/models/main"
)

# ═══════════════════════════════════════════════════════════════════════════════
# NORMALIZED DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class DatasetInfo:
    """Normalized dataset metadata."""
    name: str = ""
    dataset_type: str = ""          # training | validation | testing
    description: str = ""
    url: str = ""
    classification: str = ""        # public | confidential | restricted
    sensitive_data: bool = False
    governance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricInfo:
    """Normalized performance metric."""
    metric_type: str = ""           # accuracy | f1 | perplexity | bleu …
    value: str = ""
    slice_label: str = ""           # dataset split / subset
    confidence_interval: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedModelData:
    """
    Uniform output from any connector.

    Every field maps 1-to-1 to a CycloneDX modelCard / component field so
    the assembly step is a straightforward translation.
    """

    # ── Identity ────────────────────────────────────────────────────────────
    model_id: str = ""
    model_name: str = ""
    version: str = ""
    author: str = ""
    publisher: str = ""
    description: str = ""

    # ── Classification ──────────────────────────────────────────────────────
    pipeline_tag: str = ""              # task type (text-generation, etc.)
    library_name: str = ""
    tags: List[str] = field(default_factory=list)

    # ── Architecture ────────────────────────────────────────────────────────
    architecture_family: str = ""       # transformer | CNN | RNN …
    model_architecture: str = ""        # GPT-4 | ResNet-50 …
    approach_type: str = ""             # supervised | unsupervised | RL …

    # ── Licensing ───────────────────────────────────────────────────────────
    license_id: str = ""
    license_url: str = ""

    # ── Datasets ────────────────────────────────────────────────────────────
    datasets: List[DatasetInfo] = field(default_factory=list)

    # ── Metrics ─────────────────────────────────────────────────────────────
    metrics: List[MetricInfo] = field(default_factory=list)

    # ── Inputs / Outputs ────────────────────────────────────────────────────
    input_modalities: List[str] = field(default_factory=list)
    output_modalities: List[str] = field(default_factory=list)

    # ── Considerations ──────────────────────────────────────────────────────
    intended_users: List[str] = field(default_factory=list)
    use_cases: List[str] = field(default_factory=list)
    out_of_scope_use: List[str] = field(default_factory=list)
    technical_limitations: List[str] = field(default_factory=list)
    ethical_considerations: List[Dict[str, str]] = field(default_factory=list)
    fairness_assessments: List[Dict[str, str]] = field(default_factory=list)
    performance_tradeoffs: List[str] = field(default_factory=list)
    environmental_considerations: Dict[str, Any] = field(default_factory=dict)

    # ── Hardware ────────────────────────────────────────────────────────────
    training_hardware: str = ""
    inference_hardware: str = ""

    # ── Provenance ──────────────────────────────────────────────────────────
    base_model: str = ""
    parent_model: str = ""
    training_details: Dict[str, Any] = field(default_factory=dict)

    # ── Statistics ──────────────────────────────────────────────────────────
    downloads: int = 0
    likes: int = 0
    run_count: int = 0
    parameter_count: int = 0            # total model parameters
    parameter_dtype: str = ""           # e.g. BF16, FP32

    # ── Timestamps ──────────────────────────────────────────────────────────
    created_at: str = ""
    last_modified: str = ""

    # ── Context window ──────────────────────────────────────────────────────
    context_window: int = 0
    max_output_tokens: int = 0
    knowledge_cutoff: str = ""

    # ── Source tracking ─────────────────────────────────────────────────────
    lookup_source: str = ""
    source_url: str = ""                # website URL
    source_repo_url: str = ""           # VCS / source repository URL

    # ── Raw / extra ─────────────────────────────────────────────────────────
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeprecationResult:
    """Deprecation check result for a single model."""
    model_name: str = ""
    deprecation_found: bool = False
    model_id: str = ""
    provider: str = ""
    status: str = ""                    # deprecated | shutdown | legacy
    is_deprecated: bool = False
    severity: str = "INFO"              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    announcement_date: Optional[str] = None
    shutdown_date: Optional[str] = None
    days_until_shutdown: Optional[int] = None
    recommended_replacement: Optional[str] = None
    final_replacement: Optional[str] = None
    replacement_chain: List[str] = field(default_factory=list)
    category: Optional[str] = None
    dep_type: Optional[str] = None
    notes: str = ""


@dataclass
class AgenticFrameworkEntry:
    """One agentic framework detected in the codebase."""
    id: str = ""
    base_pkg: str = ""
    support_pkgs: List[str] = field(default_factory=list)
    assets: List[Dict[str, Any]] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# SECURE HTTP UTILITY (shared across connectors)
# ═══════════════════════════════════════════════════════════════════════════════


def _secure_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = MODEL_CARD_TIMEOUT,
    **kwargs: Any,
) -> requests.Response:
    """HTTPS GET with explicit certificate verification via *certifi*."""
    kwargs.setdefault("verify", certifi.where())
    kwargs.setdefault("timeout", timeout)
    if headers:
        kwargs["headers"] = headers
    return requests.get(url, **kwargs)


def _normalize_model_id(name: str) -> str:
    """Lower-case, slash/colon/dot → underscore/dash for cache matching."""
    return name.replace("/", "_").replace(":", "_").replace(".", "-").lower()


# ═══════════════════════════════════════════════════════════════════════════════
# BASE CONNECTOR
# ═══════════════════════════════════════════════════════════════════════════════


class BaseModelConnector(ABC):
    """
    Abstract base for every model-metadata source.

    Subclass contract:
        - Set ``name``, ``priority``, ``requires_auth``
        - Implement ``can_handle`` and ``fetch_metadata``
        - Optionally override ``is_available``

    Lower ``priority`` values are tried first in the waterfall.
    """

    name: str = "base"
    priority: int = 999
    requires_auth: bool = False

    # Fields this connector can populate (documentation / introspection)
    supported_fields: FrozenSet[str] = frozenset()

    @abstractmethod
    def can_handle(self, model_id: str) -> bool:
        """Return True if this connector *might* have data for *model_id*."""

    @abstractmethod
    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        """
        Fetch & normalize metadata.

        Returns ``None`` when the model is not found (so the registry can
        continue the waterfall).
        """

    def is_available(self) -> bool:
        """Check runtime readiness (auth configured, server reachable…)."""
        return True

    def __repr__(self) -> str:
        avail = "ready" if self.is_available() else "unavailable"
        return f"<{self.__class__.__name__} name={self.name!r} pri={self.priority} {avail}>"


# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER PREFIX REMAPPING
# ═══════════════════════════════════════════════════════════════════════════════


def remap_provider_model(model_id: str) -> Optional[str]:
    """
    Remap a provider-prefixed model name to its canonical HuggingFace ID.

    Examples:
        "groq/llama-3.3-70b-versatile" → "meta-llama/Llama-3.3-70B-Versatile"
        "ollama/llama3.1"              → "meta-llama/Llama-3.1-8B-Instruct"

    Returns None if no mapping found.
    """
    if "/" not in model_id:
        return None

    provider, model_part = model_id.split("/", 1)
    provider_lower = provider.lower()

    # 1. Exact match in PROVIDER_CANONICAL_MAP
    provider_map = PROVIDER_CANONICAL_MAP.get(provider_lower, {})
    canonical = provider_map.get(model_part.lower())
    if canonical:
        logger.info(
            f"[REMAP] {model_id!r} → {canonical!r} (exact match)"
        )
        return canonical

    # 2. Fuzzy match within provider map (find best substring match)
    model_lower = model_part.lower()
    best_match = None
    best_score = 0
    for pattern, canonical_id in provider_map.items():
        # Check if the model portion contains the pattern key
        if pattern in model_lower or model_lower in pattern:
            score = len(pattern)
            if score > best_score:
                best_score = score
                best_match = canonical_id
    if best_match:
        logger.info(
            f"[REMAP] {model_id!r} → {best_match!r} (fuzzy provider match)"
        )
        return best_match

    return None


def _hf_search_fallback(model_id: str) -> Optional[str]:
    """
    Use HuggingFace search API to find the canonical model ID.

    Strips provider prefix, searches HF, scores results by name similarity.
    Returns the best-matching HF model ID, or None.
    """
    # ── Guard: skip placeholder / generic model names ──────────────────────
    _model_part = model_id.split("/", 1)[-1] if "/" in model_id else model_id
    _placeholder_names = {"unknown-model", "unknown_model", "default", "model", "base"}
    if _model_part.lower().strip() in _placeholder_names:
        logger.debug(f"[REMAP] Skipping HF search for placeholder name: {model_id!r}")
        return None

    # ── Guard: skip API-only providers that won't have HF model cards ─────
    _api_only_providers = {
        "openai", "anthropic", "cohere", "google", "gemini",
        "groq", "together", "fireworks", "deepseek", "mistral",
        "perplexity", "anyscale", "replicate", "bedrock", "azure",
    }
    if "/" in model_id:
        _provider = model_id.split("/")[0].lower()
        if _provider in _api_only_providers:
            # Check if this model was already remapped via PROVIDER_CANONICAL_MAP
            # If not, don't search HF — these are API-hosted models
            canonical = remap_provider_model(model_id)
            if not canonical:
                logger.debug(
                    f"[REMAP] Skipping HF search for API-only provider: {model_id!r}"
                )
                return None

    # Strip provider prefix if present
    search_term = _model_part

    # Clean up common suffixes for better search
    search_clean = re.sub(r"[-_](8192|32768|131072|128k|4k)$", "", search_term, flags=re.IGNORECASE)

    url = f"{HUGGINGFACE_API_BASE}?search={search_clean}&limit=5&sort=downloads&direction=-1"
    try:
        resp = _secure_get(url, timeout=MODEL_CARD_TIMEOUT)
        if resp.status_code != 200:
            return None
        results = resp.json()
    except Exception:
        return None

    if not results:
        return None

    # Score results by name similarity
    search_lower = search_clean.lower().replace("-", "").replace("_", "")

    # Extract provider for HF org filtering
    provider = model_id.split("/")[0].lower() if "/" in model_id else ""
    preferred_orgs = PROVIDER_HF_ORG_FALLBACK.get(provider, [])

    best_id = None
    best_score = -1

    for result in results:
        hf_id = result.get("id", "")
        hf_name = hf_id.lower().replace("-", "").replace("_", "")

        # ── Strict match: the HF model name must actually contain the
        #    core search term (not just share a few characters) ──
        if search_lower not in hf_name:
            continue

        # Base score: character overlap ratio
        score = sum(1 for c in search_lower if c in hf_name) / max(len(search_lower), 1)

        # Bonus for org match
        hf_org = hf_id.split("/")[0] if "/" in hf_id else ""
        if hf_org in preferred_orgs:
            score += 0.3

        # Bonus for downloads (popular = more likely canonical)
        downloads = result.get("downloads", 0)
        if downloads > 1_000_000:
            score += 0.2
        elif downloads > 100_000:
            score += 0.1

        if score > best_score:
            best_score = score
            best_id = hf_id

    if best_id and best_score > 0.5:
        logger.info(
            f"[REMAP] {model_id!r} → {best_id!r} (HF search, score={best_score:.2f})"
        )
        return best_id

    return None


# ═══════════════════════════════════════════════════════════════════════════════
# UPSTREAM MODEL CARD FETCHER (GitHub / raw markdown for base model families)
# ═══════════════════════════════════════════════════════════════════════════════


def _resolve_upstream_model_card_url(canonical_id: str) -> Optional[str]:
    """
    Given a canonical HF model ID (e.g. ``meta-llama/Llama-3.3-70B-Instruct``),
    return the raw GitHub URL for its upstream MODEL_CARD.md if one is configured.
    """
    if "/" not in canonical_id:
        return None
    org = canonical_id.split("/")[0]
    source = UPSTREAM_MODEL_CARD_SOURCES.get(org)
    if not source:
        return None

    base_url = source.get("base_url", "")
    if not base_url:
        return None

    model_name_lower = canonical_id.split("/", 1)[1].lower()
    family_map = source.get("family_map", {})

    # Find the best-matching family key
    best_key = ""
    best_len = 0
    for pattern, family_dir in family_map.items():
        if pattern.lower() in model_name_lower and len(pattern) > best_len:
            best_key = family_dir
            best_len = len(pattern)

    if not best_key:
        return None

    url = base_url.replace("{model_family}", best_key)
    return url


def _fetch_upstream_model_card(canonical_id: str) -> str:
    """
    Fetch the upstream MODEL_CARD.md content from GitHub for a base model.

    Returns the markdown text, or empty string if unavailable.
    """
    url = _resolve_upstream_model_card_url(canonical_id)
    if not url:
        return ""

    try:
        resp = _secure_get(url, timeout=README_FETCH_TIMEOUT)
        if resp.status_code == 200:
            logger.info(
                f"[UPSTREAM] Fetched MODEL_CARD.md for {canonical_id} ({len(resp.text)} chars)"
            )
            return resp.text
        logger.debug(
            f"[UPSTREAM] MODEL_CARD.md HTTP {resp.status_code} for {canonical_id}: {url}"
        )
    except Exception as exc:
        logger.debug(f"[UPSTREAM] Error fetching MODEL_CARD.md for {canonical_id}: {exc}")
    return ""


def _extract_benchmarks_from_md(md: str) -> List[MetricInfo]:
    """
    Parse benchmark tables from an upstream MODEL_CARD.md.

    Looks for Markdown tables with columns like
    ``| Category | Benchmark | # Shots | Metric | Model... |``
    and extracts rows into ``MetricInfo`` objects.
    """
    metrics: List[MetricInfo] = []
    lines = md.splitlines()
    header_cols: List[str] = []
    model_col_idx: Optional[int] = None  # the rightmost or target model column

    in_table = False
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                in_table = False
                header_cols = []
                model_col_idx = None
            continue

        cells = [c.strip() for c in stripped.strip("|").split("|")]

        if not in_table:
            # Potential header row
            lower_cells = [c.lower() for c in cells]
            if any(kw in " ".join(lower_cells) for kw in ("benchmark", "metric", "category")):
                header_cols = cells
                # Find the model column — prefer columns matching "3.3" + "70b",
                # then "3.3", then any "instruct" column. Pick the best match.
                best_col = None
                best_score = 0
                for i, hdr in enumerate(header_cols):
                    hdr_l = hdr.lower()
                    score = 0
                    if "3.3" in hdr_l:
                        score += 3
                    if "70b" in hdr_l:
                        score += 2
                    if "instruct" in hdr_l:
                        score += 1
                    if score > best_score:
                        best_score = score
                        best_col = i
                model_col_idx = best_col
                if model_col_idx is None and len(header_cols) > 4:
                    model_col_idx = len(header_cols) - 2  # second-to-last as fallback
                in_table = True
            continue

        # Separator row (|:---|:---|)
        if all(c.replace(":", "").replace("-", "").strip() == "" for c in cells):
            continue

        # Data row
        if header_cols and model_col_idx is not None and model_col_idx < len(cells):
            benchmark = ""
            metric_type = ""
            value = cells[model_col_idx].strip() if model_col_idx < len(cells) else ""
            category = ""

            for i, hdr in enumerate(header_cols):
                hdr_l = hdr.lower()
                if i < len(cells):
                    if "benchmark" in hdr_l:
                        benchmark = cells[i].strip()
                    elif "metric" in hdr_l:
                        metric_type = cells[i].strip()
                    elif "category" in hdr_l:
                        category = cells[i].strip()

            if benchmark and value and value not in ("", "-", "—"):
                label = f"{category}/{benchmark}" if category else benchmark
                metrics.append(MetricInfo(
                    metric_type=metric_type or benchmark,
                    value=value,
                    slice_label=label,
                ))

    return metrics


def _merge_upstream_into_nd(
    nd: NormalizedModelData,
    upstream_md: str,
) -> None:
    """
    Merge data extracted from an upstream MODEL_CARD.md into the
    ``NormalizedModelData`` object.  Only fills fields that are currently empty.
    """
    if not upstream_md:
        return

    # 1. Considerations (users, use_cases, limitations, ethical, etc.)
    considerations = _extract_hf_considerations(upstream_md)

    if not nd.intended_users and considerations.get("users"):
        nd.intended_users = considerations["users"]
    if not nd.use_cases and considerations.get("use_cases"):
        nd.use_cases = considerations["use_cases"]
    if not nd.technical_limitations and considerations.get("limitations"):
        nd.technical_limitations = considerations["limitations"]
    if not nd.ethical_considerations and considerations.get("ethical"):
        nd.ethical_considerations = considerations["ethical"]
    if not nd.fairness_assessments and considerations.get("fairness"):
        nd.fairness_assessments = considerations["fairness"]
    if not nd.performance_tradeoffs and considerations.get("performance_tradeoffs"):
        nd.performance_tradeoffs = considerations["performance_tradeoffs"]
    if not nd.environmental_considerations and considerations.get("environmental"):
        nd.environmental_considerations = considerations["environmental"]
    if not nd.training_hardware and considerations.get("training_hardware"):
        nd.training_hardware = considerations["training_hardware"]
    if not nd.inference_hardware and considerations.get("inference_hardware"):
        nd.inference_hardware = considerations["inference_hardware"]
    if not nd.out_of_scope_use and considerations.get("out_of_scope_use"):
        nd.out_of_scope_use = considerations["out_of_scope_use"]

    # 2. Description (first paragraph after "## Model Information")
    if not nd.description:
        m = re.search(
            r"##\s*Model\s+Information\s*\n+(.+?)(?=\n##|\Z)",
            upstream_md,
            re.DOTALL | re.IGNORECASE,
        )
        if m:
            first_para = m.group(1).strip().split("\n\n")[0].strip()
            if len(first_para) > 20:
                nd.description = first_para

    # 3. Benchmarks / metrics
    if not nd.metrics:
        nd.metrics = _extract_benchmarks_from_md(upstream_md)

    # 4. Training data / knowledge cutoff
    if not nd.knowledge_cutoff:
        cutoff_m = re.search(
            r"(?:data\s+freshness|knowledge\s+cutoff|cutoff)[\s:of]*([A-Z][a-z]+\s+\d{4})",
            upstream_md,
            re.IGNORECASE,
        )
        if cutoff_m:
            nd.knowledge_cutoff = cutoff_m.group(1)

    # 5. Store upstream markdown for reference
    if nd.raw_metadata is None:
        nd.raw_metadata = {}
    nd.raw_metadata["upstream_model_card"] = upstream_md[:5000]  # truncate for storage

    logger.info(
        f"[UPSTREAM] Merged upstream MODEL_CARD → "
        f"desc={bool(nd.description)}, metrics={len(nd.metrics)}, "
        f"users={len(nd.intended_users)}, use_cases={len(nd.use_cases)}, "
        f"limitations={len(nd.technical_limitations)}, "
        f"ethical={len(nd.ethical_considerations)}, "
        f"hw_train={bool(nd.training_hardware)}, cutoff={nd.knowledge_cutoff!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER METADATA OVERLAY (fully dynamic — no hardcoded per-model data)
# ═══════════════════════════════════════════════════════════════════════════════


def _fetch_provider_model_info(
    provider: str, model_id: str
) -> Optional[Dict[str, Any]]:
    """
    Fetch live model metadata from any provider's OpenAI-compatible models API.

    Uses ``PROVIDER_API_CONFIG`` to look up the API base URL, auth env var,
    and URL path template for the given *provider*.  Most inference providers
    (Groq, Together, Fireworks, DeepInfra, OpenRouter, Perplexity, …) expose a
    ``GET /v1/models/{id}`` endpoint that returns at least::

        { "id", "object", "created", "owned_by", "context_window", … }

    Returns the parsed JSON dict, or ``None`` on any failure.
    """
    provider_lower = provider.lower()
    cfg = PROVIDER_API_CONFIG.get(provider_lower)
    if cfg is None:
        logger.debug(f"[PROVIDER] No API config for provider {provider!r}")
        return None

    # Auth
    auth_env = cfg.get("auth_env", "")
    api_key = os.environ.get(auth_env, "") if auth_env else ""
    if not api_key:
        logger.debug(
            f"[PROVIDER] {auth_env} not set, skipping live API for {provider}/{model_id}"
        )
        return None

    # Build URL
    api_base = cfg["api_base"].rstrip("/")
    path_template = cfg.get("models_path", "/models/{model_id}")
    path = path_template.replace("{model_id}", model_id)
    url = f"{api_base}{path}"

    # Headers
    headers: Dict[str, str] = {"Authorization": f"Bearer {api_key}"}
    for k, v in cfg.get("extra_headers", {}).items():
        headers[k] = v

    try:
        resp = _secure_get(url, timeout=MODEL_CARD_TIMEOUT, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            logger.info(
                f"[PROVIDER] Fetched live metadata for {provider}/{model_id}"
            )
            return data
        logger.debug(
            f"[PROVIDER] {provider} API returned {resp.status_code} for {model_id!r}"
        )
    except Exception as exc:
        logger.debug(f"[PROVIDER] {provider} API error for {model_id!r}: {exc}")
    return None


def _apply_provider_overlay(
    nd: NormalizedModelData,
    provider: str,
    model_part: str,
) -> None:
    """
    Enrich *nd* with provider-specific metadata fetched **dynamically**.

    The base model card data (architecture, license, datasets, metrics, etc.)
    comes from HuggingFace.  This overlay calls the provider's own API to get
    the runtime details for the specific hosted variant (context_window,
    owned_by, created, active, etc.).

    Source URL is set to the provider's docs page from ``PROVIDER_API_CONFIG``.

    Mutates *nd* in-place.
    """
    provider_lower = provider.lower()
    cfg = PROVIDER_API_CONFIG.get(provider_lower, {})

    # ── 1. Fetch live metadata from the provider's API ──────────────────────
    live = _fetch_provider_model_info(provider, model_part) or {}

    # ── 2. Map API response fields onto NormalizedModelData ─────────────────
    # Context window (most providers return this)
    ctx = live.get("context_window") or live.get("context_length")
    if ctx:
        nd.context_window = int(ctx)

    # Max output tokens (providers use different field names)
    max_out = (
        live.get("max_output_tokens")
        or live.get("max_completion_tokens")
        or (live.get("top_provider", {}) or {}).get("max_completion_tokens")
    )
    if max_out:
        nd.max_output_tokens = int(max_out)

    # Owned by / publisher
    owned_by = live.get("owned_by", "")
    if owned_by:
        nd.publisher = owned_by

    # Description from provider (if provider returns one)
    live_desc = live.get("description", "")
    if live_desc:
        base_desc = nd.description or ""
        if base_desc:
            nd.description = f"{live_desc}\n\nBase model details: {base_desc}"
        else:
            nd.description = live_desc

    # Model identity: always show the provider variant name
    nd.model_id = f"{provider}/{model_part}"
    nd.model_name = f"{provider}/{model_part}"

    # Source URL: point to the provider's model-specific docs page (dynamic)
    model_docs_url = cfg.get("model_docs_url", "")
    if model_docs_url:
        nd.source_url = model_docs_url.replace("{model_id}", model_part)
    else:
        docs_url = cfg.get("docs_url", "")
        if docs_url:
            nd.source_url = docs_url

    # Timestamps from live API
    created = live.get("created")
    if created:
        try:
            nd.created_at = datetime.utcfromtimestamp(int(created)).isoformat() + "Z"
        except (ValueError, TypeError, OSError):
            pass

    # ── 3. Extra properties (anything the API returns beyond core fields) ───
    extra: Dict[str, Any] = {}

    # Active status
    if "active" in live:
        extra["active"] = live["active"]

    # Pricing (OpenRouter, Together, some others return this)
    pricing = live.get("pricing", {})
    if isinstance(pricing, dict):
        if pricing.get("prompt"):
            extra["pricing_input_per_token"] = pricing["prompt"]
        if pricing.get("completion"):
            extra["pricing_output_per_token"] = pricing["completion"]

    # Store any other useful fields the API returned
    for key in ("architecture", "top_provider", "per_request_limits"):
        if key in live and live[key]:
            extra[key] = live[key]

    if extra:
        if not nd.raw_metadata:
            nd.raw_metadata = {}
        nd.raw_metadata["provider_overlay"] = extra

    # ── 4. Tags ─────────────────────────────────────────────────────────────
    provider_tag = f"provider:{provider_lower}"
    if provider_tag not in nd.tags:
        nd.tags.append(provider_tag)

    # Record the canonical base model this variant derives from
    canonical = nd.raw_metadata.get("_canonical_id", "") if nd.raw_metadata else ""
    if canonical and canonical != f"{provider}/{model_part}":
        variant_tag = f"variant-of:{canonical}"
    else:
        variant_tag = f"variant:{model_part}"
    if variant_tag not in nd.tags:
        nd.tags.append(variant_tag)

    logger.info(
        f"[OVERLAY] Applied {provider}/{model_part} overlay: "
        f"ctx={nd.context_window}, max_out={nd.max_output_tokens}, "
        f"owned_by={owned_by!r}"
    )



# ═══════════════════════════════════════════════════════════════════════════════
# CONNECTOR REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════


class ConnectorRegistry:
    """
    Manages a priority-ordered list of connectors.

    ``resolve()`` implements the waterfall:
        for each *available* connector (sorted by priority)
            if connector.can_handle(model_id)
                result = connector.fetch_metadata(model_id)
                if result is not None → return result
        return None
    """

    def __init__(self) -> None:
        self._connectors: List[BaseModelConnector] = []

    # ── Mutation ────────────────────────────────────────────────────────────

    def register(self, connector: BaseModelConnector) -> None:
        """Add a connector and re-sort by priority."""
        self._connectors.append(connector)
        self._connectors.sort(key=lambda c: c.priority)

    def unregister(self, name: str) -> bool:
        """Remove a connector by name. Returns True if found."""
        before = len(self._connectors)
        self._connectors = [c for c in self._connectors if c.name != name]
        return len(self._connectors) < before

    # ── Resolution ──────────────────────────────────────────────────────────

    def resolve(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        """
        Waterfall resolution: try connectors in priority order.

        Returns the first successful ``NormalizedModelData``, or ``None``.
        """
        for connector in self._connectors:
            if not connector.is_available():
                continue
            if not connector.can_handle(model_id):
                continue
            try:
                result = connector.fetch_metadata(model_id, **kwargs)
                if result is not None:
                    logger.info(
                        f"[CONNECTOR] Resolved {model_id!r} via {connector.name}"
                    )
                    return result
            except Exception as exc:
                logger.warning(
                    f"[CONNECTOR] {connector.name} failed for {model_id!r}: "
                    f"{sanitize_sensitive(str(exc))}"
                )
        return None

    # ── Introspection ───────────────────────────────────────────────────────

    def list_connectors(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": c.name,
                "priority": c.priority,
                "requires_auth": c.requires_auth,
                "available": c.is_available(),
            }
            for c in self._connectors
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# IMPLEMENTED CONNECTORS — FREE / LOCAL
# ═══════════════════════════════════════════════════════════════════════════════


# ── 1. Model Cache ──────────────────────────────────────────────────────────

class ModelCacheConnector(BaseModelConnector):
    """
    O(1) indexed lookups against the local model-card cache.

    Checks:
        1. File-based index (*_aibom.json, {provider}_{model}.json)
        2. Multi-model collection index (*_models.json)
        3. Fuzzy substring match
    """

    name = "model_cache"
    priority = 0
    requires_auth = False
    supported_fields = frozenset({
        "model_id", "model_name", "author", "license_id",
        "tags", "description", "pipeline_tag",
    })

    def __init__(self, cache_dir: Path = MODEL_CACHE_DIR) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._aibom_index: Optional[Dict[str, Path]] = None
        self._collection_index: Optional[Dict[str, Dict]] = None

    # ── Index builders ──────────────────────────────────────────────────────

    def _build_aibom_index(self) -> Dict[str, Path]:
        index: Dict[str, Path] = {}
        collection_suffix = "_models.json"
        for cache_file in self.cache_dir.glob("*.json"):
            fn = cache_file.name
            if fn.startswith(".") or fn.endswith(collection_suffix):
                continue
            fn_lower = fn.lower()
            name_part = (
                fn_lower.replace("_aibom.json", "")
                if fn_lower.endswith("_aibom.json")
                else fn_lower.replace(".json", "")
            )
            for prefix in MODEL_PROVIDER_PREFIXES:
                if name_part.startswith(prefix):
                    model_name = _normalize_model_id(name_part[len(prefix):])
                    index[model_name] = cache_file
                    index[_normalize_model_id(name_part)] = cache_file
                    break
            else:
                normalized = _normalize_model_id(name_part)
                index[normalized] = cache_file
                if "__" in name_part:
                    model_only = name_part.split("__", 1)[1]
                    index[_normalize_model_id(model_only)] = cache_file
        return index

    def _build_collection_index(self) -> Dict[str, Dict]:
        index: Dict[str, Dict] = {}
        for coll_file in self.cache_dir.glob("*_models.json"):
            if coll_file.name.startswith("."):
                continue
            try:
                data = json.loads(coll_file.read_text(encoding="utf-8"))
                provider = data.get("provider", coll_file.stem.replace("_models", ""))
                for entry in data.get("models", []):
                    mid = entry.get("model_id", "")
                    if mid:
                        copy = dict(entry)
                        copy["_provider"] = provider
                        copy["_collection_file"] = coll_file.name
                        index[_normalize_model_id(mid)] = copy
            except Exception as exc:
                logger.warning(f"Error loading collection {coll_file}: {exc}")
        return index

    @property
    def aibom_index(self) -> Dict[str, Path]:
        if self._aibom_index is None:
            self._aibom_index = self._build_aibom_index()
        return self._aibom_index

    @property
    def collection_index(self) -> Dict[str, Dict]:
        if self._collection_index is None:
            self._collection_index = self._build_collection_index()
        return self._collection_index

    def invalidate_index(self) -> None:
        self._aibom_index = None
        self._collection_index = None

    # ── Lookup helpers ──────────────────────────────────────────────────────

    def _load_aibom_file(self, cache_file: Path, source: str) -> Optional[Dict]:
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            data["_lookup_source"] = source
            data["_cache_file"] = cache_file.name
            return data
        except Exception as exc:
            logger.warning(f"Error reading cache {cache_file}: {exc}")
            return None

    def _get_exact(self, model_id: str) -> Optional[Dict]:
        safe = _normalize_model_id(model_id)
        if cache_file := self.aibom_index.get(safe):
            return self._load_aibom_file(cache_file, "local_aibom_cache")
        if coll_entry := self.collection_index.get(safe):
            result = dict(coll_entry)
            result["_lookup_source"] = "local_collection_cache"
            return result
        return None

    def _get_fuzzy(self, model_id: str) -> Optional[Dict]:
        safe = _normalize_model_id(model_id)
        for idx_name, cache_file in self.aibom_index.items():
            if safe in idx_name or idx_name in safe:
                return self._load_aibom_file(cache_file, "local_aibom_cache_fuzzy")
        for idx_name, entry in self.collection_index.items():
            if safe in idx_name or idx_name in safe:
                result = dict(entry)
                result["_lookup_source"] = "local_collection_cache_fuzzy"
                return result
        return None

    def _get_regular(self, model_id: str) -> Optional[Dict]:
        """Check regular (non-AIBOM) cache with expiry."""
        safe_id = model_id.replace("/", "__").replace("\\", "__")
        cache_path = self.cache_dir / f"{safe_id}.json"
        if not cache_path.exists():
            return None
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_time = datetime.fromisoformat(cached.get("cached_at", "2000-01-01"))
            if datetime.now() - cached_time > timedelta(days=MODEL_CACHE_EXPIRY_DAYS):
                return None
            result = cached.get("data", cached)
            result["_lookup_source"] = "cache"
            return result
        except Exception:
            return None

    def save(self, model_id: str, data: Dict, source: str = "unknown") -> None:
        safe_id = model_id.replace("/", "__").replace("\\", "__")
        cache_path = self.cache_dir / f"{safe_id}.json"
        try:
            cache_entry = {
                "model_id": model_id,
                "source": source,
                "cached_at": datetime.now().isoformat(),
                "data": data,
            }
            cache_path.write_text(
                json.dumps(cache_entry, indent=2, default=str), encoding="utf-8"
            )
            self.invalidate_index()
        except Exception as exc:
            logger.error(f"Error caching model {model_id}: {exc}")

    # ── BaseModelConnector interface ────────────────────────────────────────

    def can_handle(self, model_id: str) -> bool:  # noqa: ARG002
        return True  # always check cache first

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        raw = self._get_exact(model_id) or self._get_fuzzy(model_id) or self._get_regular(model_id)
        if raw is None:
            return None
        nd = _raw_to_normalized(raw)
        # Reject cache entries that have no meaningful data (stale / empty)
        if nd and not any([
            nd.description, nd.pipeline_tag, nd.license_id,
            nd.downloads, nd.tags, nd.author,
        ]):
            logger.info(
                f"[CACHE] Skipping empty cache entry for {model_id!r}"
            )
            return None
        return nd


# ── 2. HuggingFace Hub ──────────────────────────────────────────────────────

class HuggingFaceConnector(BaseModelConnector):
    """
    Fetches from HuggingFace Hub REST API.

    Auto-extractable fields: model name, version/revision, author/publisher,
    pipeline_tag, license, base_model, tags, datasets, metrics (model-index),
    language, library_name, config.json, README.md (model card).
    """

    name = "huggingface"
    priority = 10
    requires_auth = False  # Optional token for gated models
    supported_fields = frozenset({
        "model_id", "model_name", "version", "author", "publisher",
        "description", "pipeline_tag", "library_name", "tags",
        "architecture_family", "model_architecture", "approach_type",
        "license_id", "datasets", "metrics",
        "input_modalities", "output_modalities",
        "intended_users", "use_cases", "technical_limitations",
        "ethical_considerations", "base_model",
        "downloads", "likes", "created_at", "last_modified",
    })

    def can_handle(self, model_id: str) -> bool:  # noqa: ARG002
        return True  # HF is a broad fallback

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        hf_token: Optional[str] = kwargs.get("hf_token") or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
        url = f"{HUGGINGFACE_API_BASE}/{model_id}"
        headers: Dict[str, str] = {}
        if hf_token:
            headers["Authorization"] = f"Bearer {hf_token}"

        try:
            resp = _secure_get(url, headers=headers or None, timeout=MODEL_CARD_TIMEOUT)
            if resp.status_code == 404:
                return None
            if resp.status_code == 401:
                # Gated model — try without auth to get at least basic info,
                # or fall back to search API for partial metadata
                logger.info(f"HuggingFace gated model {model_id}, trying search fallback")
                return self._fetch_gated_model_via_search(model_id, headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except requests.Timeout:
            logger.error("HuggingFace timeout", extra={"model_id": model_id})
            return None
        except Exception as exc:
            logger.error(
                "HuggingFace fetch error",
                extra={"model_id": model_id, "error": sanitize_sensitive(str(exc))},
            )
            return None

        # Parse card_data for rich metadata
        card_data = data.get("cardData", {}) or {}

        # Attempt README fetch
        readme = ""
        try:
            readme_url = f"{HUGGINGFACE_RAW_BASE}/{model_id}/raw/main/README.md"
            readme_resp = _secure_get(
                readme_url, headers=headers or None, timeout=README_FETCH_TIMEOUT
            )
            if readme_resp.status_code == 200:
                readme = readme_resp.text
        except Exception:
            pass

        # Extract datasets from card_data
        datasets = _extract_hf_datasets(card_data)

        # Extract metrics from model-index in card_data
        metrics = _extract_hf_metrics(card_data)

        # Extract considerations from README
        considerations = _extract_hf_considerations(readme)

        # Build normalized object
        nd = NormalizedModelData(
            model_id=data.get("id", model_id),
            model_name=data.get("modelId", model_id),
            version=data.get("sha", ""),
            author=data.get("author", ""),
            publisher=data.get("author", ""),
            description=card_data.get("description", ""),
            pipeline_tag=data.get("pipeline_tag", ""),
            library_name=data.get("library_name", ""),
            tags=data.get("tags", []),
            license_id=data.get("license", card_data.get("license", "")),
            license_url=f"https://huggingface.co/{model_id}/blob/main/LICENSE" if data.get("license") else "",
            datasets=datasets,
            metrics=metrics,
            input_modalities=card_data.get("input_modalities", []),
            output_modalities=card_data.get("output_modalities", []),
            base_model=(
                card_data.get("base_model", [""])[0]
                if isinstance(card_data.get("base_model"), list)
                else card_data.get("base_model", "")
            ),
            downloads=data.get("downloads", 0),
            likes=data.get("likes", 0),
            created_at=data.get("createdAt", ""),
            last_modified=data.get("lastModified", ""),
            lookup_source="huggingface",
            source_url=f"https://huggingface.co/{model_id}",
            source_repo_url=f"https://huggingface.co/{model_id}",
            intended_users=considerations.get("users", []),
            use_cases=considerations.get("use_cases", []),
            out_of_scope_use=considerations.get("out_of_scope_use", []),
            technical_limitations=considerations.get("limitations", []),
            ethical_considerations=considerations.get("ethical", []),
            fairness_assessments=considerations.get("fairness", []),
            performance_tradeoffs=considerations.get("performance_tradeoffs", []),
            environmental_considerations=considerations.get("environmental", {}),
            training_hardware=considerations.get("training_hardware", ""),
            inference_hardware=considerations.get("inference_hardware", ""),
            raw_metadata={
                "card_data": card_data,
                "config": data.get("config", {}),
                "readme_content": readme,
                "siblings": data.get("siblings", []),
                "spaces": data.get("spaces", []),
                "gated": data.get("gated", False),
                "disabled": data.get("disabled", False),
                "transformersInfo": data.get("transformersInfo", {}),
                "safetensors": data.get("safetensors", {}),
                "widgetData": data.get("widgetData", []),
                "_raw_response": data,
            },
        )

        # ── Parameter count from safetensors ────────────────────────────────
        safetensors = data.get("safetensors", {}) or {}
        if safetensors.get("total"):
            nd.parameter_count = int(safetensors["total"])
            params = safetensors.get("parameters", {})
            if isinstance(params, dict) and params:
                nd.parameter_dtype = next(iter(params))  # e.g. "BF16"

        # ── Infer inputs / outputs from pipeline_tag when missing ───────────
        if not nd.input_modalities or not nd.output_modalities:
            _in, _out = _infer_modalities_from_pipeline(nd.pipeline_tag)
            if not nd.input_modalities:
                nd.input_modalities = _in
            if not nd.output_modalities:
                nd.output_modalities = _out

        # Infer architecture from tags / card_data + top-level config
        merged_card = {**card_data, "config": data.get("config", {})}
        nd.architecture_family = _infer_architecture_family(nd.tags, merged_card)
        nd.model_architecture = _infer_model_architecture(model_id, nd.tags, merged_card)
        nd.approach_type = _infer_approach_type(nd.pipeline_tag, nd.tags)

        return nd

    def _fetch_gated_model_via_search(
        self, model_id: str, headers: Dict[str, str]
    ) -> Optional[NormalizedModelData]:
        """
        For gated models that return 401, use the HF search API which
        returns basic metadata (tags, downloads, pipeline_tag, etc.)
        without requiring auth.
        """
        search_url = (
            f"{HUGGINGFACE_API_BASE}?search={model_id.split('/')[-1]}"
            f"&author={model_id.split('/')[0]}&limit=1"
        )
        try:
            resp = _secure_get(search_url, timeout=MODEL_CARD_TIMEOUT)
            if resp.status_code != 200:
                return None
            results = resp.json()
            if not results:
                return None

            data = results[0]
            model_hf_id = data.get("modelId", data.get("id", model_id))

            # Try README (often accessible even for gated models)
            readme = ""
            try:
                readme_url = f"{HUGGINGFACE_RAW_BASE}/{model_hf_id}/raw/main/README.md"
                readme_resp = _secure_get(
                    readme_url, headers=headers or None, timeout=README_FETCH_TIMEOUT
                )
                if readme_resp.status_code == 200:
                    readme = readme_resp.text
            except Exception:
                pass

            considerations = _extract_hf_considerations(readme)
            tags = data.get("tags", [])

            # Extract base_model from tags
            base_model = ""
            for tag in tags:
                if tag.startswith("base_model:"):
                    base_model = tag.split(":", 1)[1]
                    if base_model.startswith("finetune:"):
                        base_model = base_model.split(":", 1)[1]
                    break

            # Extract license from tags
            license_id = ""
            for tag in tags:
                if tag.startswith("license:"):
                    license_id = tag.split(":", 1)[1]
                    break

            nd = NormalizedModelData(
                model_id=model_hf_id,
                model_name=model_hf_id,
                author=model_hf_id.split("/")[0] if "/" in model_hf_id else "",
                publisher=model_hf_id.split("/")[0] if "/" in model_hf_id else "",
                pipeline_tag=data.get("pipeline_tag", ""),
                library_name=data.get("library_name", ""),
                tags=tags,
                license_id=license_id,
                base_model=base_model,
                downloads=data.get("downloads", 0),
                likes=data.get("likes", 0),
                created_at=data.get("createdAt", ""),
                last_modified=data.get("lastModified", ""),
                lookup_source="huggingface_gated",
                source_url=f"https://huggingface.co/{model_hf_id}",
                source_repo_url=f"https://huggingface.co/{model_hf_id}",
                intended_users=considerations.get("users", []),
                use_cases=considerations.get("use_cases", []),
                out_of_scope_use=considerations.get("out_of_scope_use", []),
                technical_limitations=considerations.get("limitations", []),
                ethical_considerations=considerations.get("ethical", []),
                fairness_assessments=considerations.get("fairness", []),
                performance_tradeoffs=considerations.get("performance_tradeoffs", []),
                environmental_considerations=considerations.get("environmental", {}),
                training_hardware=considerations.get("training_hardware", ""),
                inference_hardware=considerations.get("inference_hardware", ""),
                raw_metadata={
                    "search_result": data,
                    "readme_content": readme,
                    "gated": True,
                },
            )

            nd.architecture_family = _infer_architecture_family(nd.tags, {})
            nd.model_architecture = _infer_model_architecture(model_hf_id, nd.tags, {})
            nd.approach_type = _infer_approach_type(nd.pipeline_tag, nd.tags)

            logger.info(
                f"[HF] Resolved gated model {model_id} via search → {model_hf_id}"
            )
            return nd

        except Exception as exc:
            logger.error(
                "HuggingFace gated search fallback error",
                extra={"model_id": model_id, "error": sanitize_sensitive(str(exc))},
            )
            return None


# ── 3. Replicate ────────────────────────────────────────────────────────────

class ReplicateConnector(BaseModelConnector):
    """
    Fetches model metadata from Replicate REST API.

    Free for metadata queries. ``GET /v1/models/{owner}/{name}``
    Returns: name, description, owner, visibility, latest_version,
    run_count, github_url, paper_url, license_url.
    """

    name = "replicate"
    priority = 15
    requires_auth = False  # Optional token for higher rate limits
    supported_fields = frozenset({
        "model_id", "model_name", "author", "description",
        "license_id", "run_count", "source_url",
    })

    _OWNER_MODEL_RE = re.compile(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9._-]+$")

    def can_handle(self, model_id: str) -> bool:
        # Replicate models are "owner/model-name" format
        return bool(self._OWNER_MODEL_RE.match(model_id.split(":")[0]))

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        # Strip version hash if present (owner/model:version)
        base_id = model_id.split(":")[0]
        url = f"{REPLICATE_API_BASE}/models/{base_id}"
        token = kwargs.get("replicate_token") or os.environ.get("REPLICATE_API_TOKEN")
        headers: Dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            resp = _secure_get(url, headers=headers or None, timeout=MODEL_CARD_TIMEOUT)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except Exception as exc:
            logger.debug(f"Replicate fetch error for {model_id}: {sanitize_sensitive(str(exc))}")
            return None

        latest = data.get("latest_version") or {}
        return NormalizedModelData(
            model_id=data.get("url", model_id),
            model_name=data.get("name", base_id.split("/")[-1]),
            author=data.get("owner", base_id.split("/")[0]),
            publisher=data.get("owner", ""),
            description=data.get("description", ""),
            license_id=data.get("license_url", ""),
            run_count=data.get("run_count", 0),
            version=latest.get("id", ""),
            created_at=latest.get("created_at", ""),
            lookup_source="replicate",
            source_url=data.get("url", f"https://replicate.com/{base_id}"),
            raw_metadata={"_raw_response": data},
        )


# ── 4. Azure AI Catalog ────────────────────────────────────────────────────

class AzureAICatalogConnector(BaseModelConnector):
    """
    Searches the Azure AI Foundry public catalog.

    Free & unauthenticated. Returns: name, publisher, version,
    license, task, description.
    """

    name = "azure_ai_catalog"
    priority = 20
    requires_auth = False
    supported_fields = frozenset({
        "model_id", "model_name", "publisher", "description",
        "version", "pipeline_tag", "license_id",
    })

    def can_handle(self, model_id: str) -> bool:  # noqa: ARG002
        return True  # broad catalog search

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        search_url = f"{AZURE_AI_CATALOG_API}?search={model_id}"
        try:
            resp = _secure_get(
                search_url,
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
                timeout=MODEL_CARD_TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
        except Exception as exc:
            logger.debug(f"Azure catalog error for {model_id}: {exc}")
            return None

        models = data.get("models", data.get("items", []))
        if not models:
            return None

        model_id_lower = model_id.lower()
        for m in models:
            mname = m.get("name", "").lower()
            if model_id_lower in mname or mname in model_id_lower:
                return NormalizedModelData(
                    model_id=m.get("id", model_id),
                    model_name=m.get("name", model_id),
                    description=m.get("description", ""),
                    publisher=m.get("publisher", ""),
                    version=m.get("version", ""),
                    pipeline_tag=m.get("task", ""),
                    license_id=m.get("license", ""),
                    lookup_source="azure_ai_foundry",
                    source_url=f"https://ai.azure.com/explore/models/{m.get('name', model_id)}",
                    raw_metadata={"_raw_response": m},
                )
        return None


# ── 5. TensorFlow Hub ──────────────────────────────────────────────────────

class TFHubConnector(BaseModelConnector):
    """
    Queries TensorFlow Hub for model metadata.

    Free & public. Useful for TF SavedModel assets.
    """

    name = "tfhub"
    priority = 25
    requires_auth = False
    supported_fields = frozenset({
        "model_id", "model_name", "publisher", "description",
        "pipeline_tag",
    })

    _TF_PATTERNS = re.compile(
        r"(google|tensorflow|keras|mediapipe)", re.IGNORECASE
    )

    def can_handle(self, model_id: str) -> bool:
        return bool(self._TF_PATTERNS.search(model_id))

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        # TF Hub models identified by publisher/model-name
        search_url = f"{TFHUB_API_BASE}/models?q={model_id}"
        try:
            resp = _secure_get(search_url, timeout=MODEL_CARD_TIMEOUT)
            if resp.status_code != 200:
                return None
            results = resp.json()
        except Exception:
            return None

        # TF Hub API may return list or object
        models = results if isinstance(results, list) else results.get("models", [])
        if not models:
            return None

        best = models[0]
        return NormalizedModelData(
            model_id=best.get("handle", model_id),
            model_name=best.get("name", model_id),
            publisher=best.get("publisher", ""),
            description=best.get("description", ""),
            pipeline_tag=best.get("task", ""),
            tags=best.get("tags", []),
            lookup_source="tfhub",
            source_url=f"https://tfhub.dev/{best.get('handle', model_id)}",
            raw_metadata={"_raw_response": best},
        )


# ── 6. ONNX Model Zoo ──────────────────────────────────────────────────────

class ONNXModelZooConnector(BaseModelConnector):
    """
    Fetches model metadata from the ONNX Model Zoo (GitHub-hosted).

    Parses the model listing JSON from the onnx/models repository.
    """

    name = "onnx_model_zoo"
    priority = 30
    requires_auth = False
    supported_fields = frozenset({
        "model_id", "model_name", "description",
        "pipeline_tag", "architecture_family",
    })

    _ONNX_PATTERNS = re.compile(r"(onnx|\.onnx)", re.IGNORECASE)

    def can_handle(self, model_id: str) -> bool:
        return bool(self._ONNX_PATTERNS.search(model_id))

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        # Try fetching the ONNX Model Zoo manifest
        manifest_url = f"{ONNX_ZOO_RAW_BASE}/ONNX_HUB_MANIFEST.json"
        try:
            resp = _secure_get(manifest_url, timeout=MODEL_CARD_TIMEOUT)
            if resp.status_code != 200:
                return None
            manifest = resp.json()
        except Exception:
            return None

        model_id_lower = model_id.lower().replace(".onnx", "")
        for entry in manifest:
            name = entry.get("model", "").lower()
            if model_id_lower in name or name in model_id_lower:
                return NormalizedModelData(
                    model_id=entry.get("model_path", model_id),
                    model_name=entry.get("model", model_id),
                    description=entry.get("description", ""),
                    pipeline_tag=entry.get("task", ""),
                    architecture_family=entry.get("architecture", ""),
                    tags=entry.get("tags", []),
                    lookup_source="onnx_model_zoo",
                    source_url=f"https://github.com/onnx/models/tree/main/{entry.get('model_path', '')}",
                    raw_metadata={"_raw_response": entry},
                )
        return None


# ── 7. Git Repo (session-based) ────────────────────────────────────────────

class GitRepoConnector(BaseModelConnector):
    """
    Reads model metadata from the already-scanned repository data
    stored in ``session.extra`` (packages, manifests, config files).

    Does NOT re-scan; pulls enrichment data that previous endpoints
    have already gathered.
    """

    name = "git_repo"
    priority = 35
    requires_auth = False
    supported_fields = frozenset({"model_id", "model_name", "tags", "license_id"})

    def can_handle(self, model_id: str) -> bool:  # noqa: ARG002
        return True

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        session_extra: Dict = kwargs.get("session_extra", {})
        if not session_extra:
            return None

        # Check if packages data has info about this model
        packages = session_extra.get("packages", {})
        if not packages:
            return None

        model_lower = model_id.lower()
        for pkg_name, pkg_data in packages.items():
            if model_lower in pkg_name.lower():
                return NormalizedModelData(
                    model_id=model_id,
                    model_name=model_id,
                    description=pkg_data.get("description", ""),
                    license_id=pkg_data.get("license", ""),
                    version=pkg_data.get("version", ""),
                    lookup_source="git_repo_session",
                    raw_metadata={"package_data": pkg_data},
                )
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# STUB CONNECTORS — AUTH-REQUIRED / FUTURE
# ═══════════════════════════════════════════════════════════════════════════════


class _StubConnector(BaseModelConnector):
    """
    Base for connectors that are not yet fully implemented.

    ``is_available()`` returns ``False`` unless the required env var
    is set, so the waterfall silently skips them.
    """

    _env_var: str = ""

    def is_available(self) -> bool:
        if not self._env_var:
            return False
        return bool(os.environ.get(self._env_var))

    def can_handle(self, model_id: str) -> bool:  # noqa: ARG002
        return True

    def fetch_metadata(
        self, model_id: str, **kwargs: Any
    ) -> Optional[NormalizedModelData]:
        # Stub — to be implemented when auth is available
        return None


class PyTorchHubConnector(_StubConnector):
    """
    PyTorch Hub — ``torch.hub.list()`` / hubconf.py parsing.

    Very limited metadata API; primarily just lists available models
    from GitHub repos that publish a hubconf.py.

    Estimated field coverage: ~10-15%.
    """
    name = "pytorch_hub"
    priority = 40
    requires_auth = False
    _env_var = ""

    def is_available(self) -> bool:
        return False  # No reliable public REST API yet

    supported_fields = frozenset({"model_id", "model_name"})


class KaggleConnector(_StubConnector):
    """
    Kaggle Models API — ``kaggle.api.model_get()``.

    Free with API key (free account).  Returns: name, description,
    author, tags, versions, framework.

    Estimated field coverage: ~20-25%.
    Env var: ``KAGGLE_KEY``
    """
    name = "kaggle"
    priority = 45
    requires_auth = True
    _env_var = "KAGGLE_KEY"
    supported_fields = frozenset({
        "model_id", "model_name", "author", "description", "tags",
    })


class MLflowConnector(_StubConnector):
    """
    MLflow Model Registry — ``mlflow.tracking.MlflowClient``.

    Free (self-hosted OSS), requires running MLflow server URL.

    Auto-extractable: model name, version, run_id, parameters,
    metrics, tags, artifacts, model signature, conda.yaml deps.

    Estimated field coverage: ~50-60%.
    Env var: ``MLFLOW_TRACKING_URI``
    """
    name = "mlflow"
    priority = 50
    requires_auth = True
    _env_var = "MLFLOW_TRACKING_URI"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "description",
        "metrics", "datasets", "tags",
    })


class SageMakerConnector(_StubConnector):
    """
    AWS SageMaker Model Registry — ``boto3`` SageMaker API.

    Requires AWS credentials.

    Auto-extractable: model package name, version, status, description,
    inference spec, custom metadata, model data URL (S3).

    Estimated field coverage: ~40-50%.
    Env var: ``AWS_ACCESS_KEY_ID``
    """
    name = "sagemaker"
    priority = 55
    requires_auth = True
    _env_var = "AWS_ACCESS_KEY_ID"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "description", "metrics",
    })


class AzureMLConnector(_StubConnector):
    """
    Azure Machine Learning — ``azure-ai-ml`` SDK v2.

    Requires Azure subscription.

    Auto-extractable: model name, version, tags, properties,
    model type, training job details, registered datasets, environment.

    Estimated field coverage: ~40-50%.
    Env var: ``AZURE_ML_WORKSPACE``
    """
    name = "azure_ml"
    priority = 60
    requires_auth = True
    _env_var = "AZURE_ML_WORKSPACE"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "description",
        "tags", "datasets", "metrics",
    })


class VertexAIConnector(_StubConnector):
    """
    Google Vertex AI Model Registry — Vertex AI SDK.

    Requires GCP credentials.

    Auto-extractable: model name, version, description, labels,
    artifact URI, container spec, explanation spec.

    Estimated field coverage: ~40-50%.
    Env var: ``GOOGLE_APPLICATION_CREDENTIALS``
    """
    name = "vertex_ai"
    priority = 65
    requires_auth = True
    _env_var = "GOOGLE_APPLICATION_CREDENTIALS"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "description", "tags",
    })


class WandBConnector(_StubConnector):
    """
    Weights & Biases — ``wandb`` SDK + GraphQL API.

    Free tier available; requires API key.

    Auto-extractable: config (hyperparameters), summary metrics,
    system metrics (GPU), artifacts, Git info, model registry.

    Estimated field coverage: ~55-65%.
    Env var: ``WANDB_API_KEY``
    """
    name = "wandb"
    priority = 70
    requires_auth = True
    _env_var = "WANDB_API_KEY"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "description",
        "metrics", "tags",
    })


class OCIRegistryConnector(_StubConnector):
    """
    OCI / Docker Registry — OCI Distribution Spec API.

    Free for public registries.

    Auto-extractable: image name, tags, digest, layers, labels,
    installed packages, base image, entrypoint.

    Estimated field coverage: ~25-40%.
    Env var: ``OCI_REGISTRY_URL``
    """
    name = "oci_registry"
    priority = 75
    requires_auth = True
    _env_var = "OCI_REGISTRY_URL"
    supported_fields = frozenset({
        "model_id", "model_name", "version", "tags",
    })


# ═══════════════════════════════════════════════════════════════════════════════
# HF METADATA EXTRACTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════


def _extract_hf_datasets(card_data: Dict) -> List[DatasetInfo]:
    """Extract dataset references from HuggingFace card_data."""
    datasets: List[DatasetInfo] = []
    raw_datasets = card_data.get("datasets", card_data.get("dataset_info", []))
    if isinstance(raw_datasets, str):
        raw_datasets = [raw_datasets]
    if isinstance(raw_datasets, list):
        for ds in raw_datasets:
            if isinstance(ds, str):
                datasets.append(DatasetInfo(
                    name=ds,
                    dataset_type="training",
                    url=f"https://huggingface.co/datasets/{ds}",
                    classification="public",
                ))
            elif isinstance(ds, dict):
                datasets.append(DatasetInfo(
                    name=ds.get("name", ds.get("dataset_name", "")),
                    dataset_type=ds.get("type", "training"),
                    description=ds.get("description", ""),
                    url=ds.get("url", ""),
                    classification=ds.get("classification", "public"),
                ))
    return datasets


def _extract_hf_metrics(card_data: Dict) -> List[MetricInfo]:
    """Extract metrics from HuggingFace model-index."""
    metrics: List[MetricInfo] = []
    model_index = card_data.get("model-index", card_data.get("model_index", []))
    if isinstance(model_index, list):
        for entry in model_index:
            for result in entry.get("results", []):
                for m in result.get("metrics", []):
                    metrics.append(MetricInfo(
                        metric_type=m.get("type", m.get("name", "")),
                        value=str(m.get("value", "")),
                        slice_label=result.get("dataset", {}).get("name", ""),
                    ))
    return metrics


def _extract_hf_considerations(readme: str) -> Dict[str, Any]:
    """
    Heuristic extraction of considerations, hardware, environmental, and
    performance sections from a HuggingFace README.

    Returns a dict with keys: users, use_cases, limitations, ethical,
    fairness, performance_tradeoffs, environmental, training_hardware,
    inference_hardware.
    """
    sections: Dict[str, Any] = {
        "users": [],
        "use_cases": [],
        "out_of_scope_use": [],
        "limitations": [],
        "ethical": [],
        "fairness": [],
        "performance_tradeoffs": [],
        "environmental": {},
        "training_hardware": "",
        "inference_hardware": "",
    }
    if not readme:
        return sections

    current_section: Optional[str] = None
    section_map = {
        "intended use": "use_cases",
        "intended users": "users",
        "use cases": "use_cases",
        "uses": "use_cases",
        "limitations": "limitations",
        "technical limitations": "limitations",
        "known limitations": "limitations",
        "out of scope": "out_of_scope_use",
        "out-of-scope": "out_of_scope_use",
        "out of scope use": "out_of_scope_use",
        "misuse": "out_of_scope_use",
        "ethical considerations": "ethical",
        "bias": "ethical",
        "risks": "ethical",
        "responsibility": "ethical",
        "safety": "ethical",
        "fairness": "fairness",
        "fairness evaluation": "fairness",
        "fairness assessment": "fairness",
        "performance tradeoff": "performance_tradeoffs",
        "performance trade-off": "performance_tradeoffs",
        "speed vs accuracy": "performance_tradeoffs",
        "environmental impact": "environmental",
        "carbon footprint": "environmental",
        "carbon emission": "environmental",
        "energy consumption": "environmental",
        "hardware": "hardware",
        "training hardware": "training_hardware",
        "training infrastructure": "training_hardware",
        "compute": "training_hardware",
        "inference hardware": "inference_hardware",
        "deployment": "inference_hardware",
    }

    # Collect raw text per section for hardware/env paragraph extraction
    _section_lines: Dict[str, List[str]] = {}

    for line in readme.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            heading_text = stripped.lstrip("#").strip().lower()
            current_section = None
            for pattern, section_key in section_map.items():
                if pattern in heading_text:
                    current_section = section_key
                    break
            if current_section:
                _section_lines.setdefault(current_section, [])
        elif current_section:
            _section_lines.setdefault(current_section, []).append(stripped)
            # Bullet items: "-", "•", or single "* " (not "**bold**")
            if re.match(r"^(?:[-•]|\*(?!\*))\s", stripped):
                item = re.sub(r"\*\*([^*]+)\*\*", r"\1", stripped.lstrip("-*• ").strip())
                if item and len(item) > 3:
                    if current_section == "ethical":
                        sections["ethical"].append({"name": item, "mitigation_strategy": ""})
                    elif current_section == "fairness":
                        sections["fairness"].append({"name": item, "mitigationStrategy": ""})
                    elif current_section in ("performance_tradeoffs",):
                        sections["performance_tradeoffs"].append(item)
                    elif current_section in ("users", "use_cases", "limitations", "out_of_scope_use"):
                        sections[current_section].append(item)

    # ── Strip HTML comments and placeholder text ────────────────────────────
    # HuggingFace template READMEs have HTML comments like:
    # <!-- Address questions around how the model is intended to be used -->
    # These are useless placeholders and must be removed.
    _placeholder_re = re.compile(r'<!--.*?-->', re.DOTALL)
    _more_info_re = re.compile(r'\[More Information Needed\]', re.IGNORECASE)

    def _is_placeholder(text: str) -> bool:
        """Return True if text is just an HTML comment template or placeholder."""
        cleaned = _placeholder_re.sub('', text).strip()
        cleaned = _more_info_re.sub('', cleaned).strip()
        return len(cleaned) < 10

    # Clean each list-type section: remove placeholder entries
    for key in ('users', 'use_cases', 'limitations', 'out_of_scope_use'):
        sections[key] = [item for item in sections[key] if not _is_placeholder(item)]
    sections['ethical'] = [e for e in sections['ethical'] if not _is_placeholder(e.get('name', ''))]
    sections['fairness'] = [f for f in sections['fairness'] if not _is_placeholder(f.get('name', ''))]
    sections['performance_tradeoffs'] = [
        t for t in sections['performance_tradeoffs'] if not _is_placeholder(t)
    ]

    # For list-type sections that got no bullet items, fall back to
    # paragraph text (split on bold `**...**` sub-headings if present).
    def _paragraphs_from_lines(lines: List[str]) -> List[str]:
        """Split collected lines into clean paragraph items."""
        text = " ".join(l for l in lines if l and not l.startswith("|")).strip()
        if not text:
            return []
        # Strip markdown bold markers
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        # Also strip stray escaped markdown
        text = re.sub(r"\\?\*\\?\*", "", text)
        text = text.strip()
        if not text or len(text) < 16:
            return []
        return [text]

    for key in ("users", "use_cases", "limitations", "out_of_scope_use"):
        if not sections[key] and key in _section_lines:
            sections[key] = _paragraphs_from_lines(_section_lines[key])
    if not sections["ethical"] and "ethical" in _section_lines:
        for para in _paragraphs_from_lines(_section_lines["ethical"]):
            sections["ethical"].append({"name": para, "mitigation_strategy": ""})
    if not sections["fairness"] and "fairness" in _section_lines:
        for para in _paragraphs_from_lines(_section_lines["fairness"]):
            sections["fairness"].append({"name": para, "mitigationStrategy": ""})
    if not sections["performance_tradeoffs"] and "performance_tradeoffs" in _section_lines:
        sections["performance_tradeoffs"] = _paragraphs_from_lines(
            _section_lines["performance_tradeoffs"]
        )

    # Extract hardware info from collected lines
    def _join_section(key: str) -> str:
        raw = " ".join(l for l in _section_lines.get(key, []) if l).strip()
        return re.sub(r"\*\*([^*]+)\*\*", r"\1", raw)

    hw_text = _join_section("hardware")
    if hw_text:
        lower = hw_text.lower()
        if "training" in lower and not sections["training_hardware"]:
            sections["training_hardware"] = hw_text
        if "inference" in lower and not sections["inference_hardware"]:
            sections["inference_hardware"] = hw_text
    if not sections["training_hardware"]:
        sections["training_hardware"] = _join_section("training_hardware")
    if not sections["inference_hardware"]:
        sections["inference_hardware"] = _join_section("inference_hardware")

    # Environmental
    env_text = _join_section("environmental")
    if not env_text and hw_text:
        # CO2 / emissions data sometimes lives inside the hardware section
        import re as _re
        if _re.search(r'CO2|emission|greenhouse|carbon', hw_text, _re.IGNORECASE):
            env_text = hw_text
    if env_text:
        sections["environmental"] = {"description": env_text}
        # Try to extract CO2 numbers
        import re as _re
        co2_match = _re.search(r'\*{0,2}([\d,]+\.?\d*)\*{0,2}\s*(tons?|kg|g|t)\s*CO2', env_text, _re.IGNORECASE)
        if co2_match:
            raw_val = co2_match.group(1).replace(",", "")
            unit = co2_match.group(2).lower()
            # Normalise to metric tons
            if unit in ("ton", "tons"):
                sections["environmental"]["co2_tons"] = raw_val
            else:
                sections["environmental"]["co2_kg"] = raw_val

    return sections


def _infer_architecture_family(tags: List[str], card_data: Dict) -> str:
    """Infer architecture family (transformer, CNN, etc.) from tags."""
    arch_keywords = {
        "transformer": "transformer",
        "bert": "transformer",
        "gpt": "transformer",
        "t5": "transformer",
        "llama": "transformer",
        "mistral": "transformer",
        "cnn": "cnn",
        "resnet": "cnn",
        "vgg": "cnn",
        "efficientnet": "cnn",
        "rnn": "rnn",
        "lstm": "rnn",
        "gru": "rnn",
        "diffusion": "diffusion",
        "gan": "gan",
        "vae": "vae",
        "mamba": "state-space",
    }
    all_text = " ".join(tags).lower() + " " + str(card_data).lower()
    for keyword, family in arch_keywords.items():
        if keyword in all_text:
            return family
    return ""


def _infer_model_architecture(
    model_id: str, tags: List[str], card_data: Dict
) -> str:
    """Infer specific model architecture from model ID and tags."""
    architectures = card_data.get("architectures", [])
    if architectures:
        return architectures[0] if isinstance(architectures, list) else str(architectures)

    config = card_data.get("config", {})
    if isinstance(config, dict):
        arch = config.get("architectures", config.get("model_type", ""))
        if isinstance(arch, list) and arch:
            return arch[0]
        if arch:
            return str(arch)

    return ""


def _infer_approach_type(pipeline_tag: str, tags: List[str]) -> str:
    """Infer learning approach from pipeline tag and tags."""
    tag_text = " ".join(tags).lower() + " " + pipeline_tag.lower()

    if any(kw in tag_text for kw in ("supervised", "classification", "regression", "ner")):
        return "supervised"
    if any(kw in tag_text for kw in ("unsupervised", "clustering")):
        return "unsupervised"
    if any(kw in tag_text for kw in ("reinforcement", "rl", "rlhf")):
        return "reinforcement-learning"
    if any(kw in tag_text for kw in ("self-supervised", "contrastive")):
        return "self-supervised"
    if any(kw in tag_text for kw in ("semi-supervised",)):
        return "semi-supervised"
    # Most LLMs are a mix; default to supervised for fine-tuned
    if any(kw in tag_text for kw in ("text-generation", "causal-lm", "chat")):
        return "supervised"
    return ""


# ── Pipeline-tag → input/output modality mapping ───────────────────────────
_PIPELINE_MODALITIES: Dict[str, Tuple[List[str], List[str]]] = {
    "text-generation":          (["text"], ["text"]),
    "text2text-generation":     (["text"], ["text"]),
    "text-classification":      (["text"], ["text"]),
    "token-classification":     (["text"], ["text"]),
    "question-answering":       (["text"], ["text"]),
    "summarization":            (["text"], ["text"]),
    "translation":              (["text"], ["text"]),
    "fill-mask":                (["text"], ["text"]),
    "conversational":           (["text"], ["text"]),
    "sentence-similarity":      (["text"], ["text"]),
    "table-question-answering": (["text"], ["text"]),
    "feature-extraction":       (["text"], ["tensor"]),
    "zero-shot-classification": (["text"], ["text"]),
    "image-classification":     (["image"], ["text"]),
    "object-detection":         (["image"], ["text"]),
    "image-segmentation":       (["image"], ["image"]),
    "image-to-text":            (["image"], ["text"]),
    "text-to-image":            (["text"], ["image"]),
    "image-to-image":           (["image"], ["image"]),
    "text-to-speech":           (["text"], ["audio"]),
    "automatic-speech-recognition": (["audio"], ["text"]),
    "audio-classification":     (["audio"], ["text"]),
    "text-to-audio":            (["text"], ["audio"]),
    "text-to-video":            (["text"], ["video"]),
    "visual-question-answering": (["image", "text"], ["text"]),
    "document-question-answering": (["image", "text"], ["text"]),
    "video-classification":     (["video"], ["text"]),
    "depth-estimation":         (["image"], ["image"]),
    "mask-generation":          (["image"], ["image"]),
}


def _infer_modalities_from_pipeline(
    pipeline_tag: str,
) -> Tuple[List[str], List[str]]:
    """Return (inputs, outputs) modality lists inferred from *pipeline_tag*."""
    entry = _PIPELINE_MODALITIES.get(pipeline_tag.lower().strip(), ([], []))
    return list(entry[0]), list(entry[1])


def _raw_to_normalized(raw: Dict) -> NormalizedModelData:
    """Convert a raw cache / API dict into ``NormalizedModelData``.

    This handles both:
      - Direct HF API responses (top-level keys: modelId, pipeline_tag, etc.)
      - Cached entries that may wrap the raw response inside a ``data`` key
        with rich nested ``card_data`` / ``config`` sub-objects.
    """
    # card_data may live at top-level or inside raw_metadata / _raw_response
    card_data = raw.get("cardData", raw.get("card_data", {})) or {}
    _raw_response = raw.get("_raw_response", raw)

    # Model identity
    model_id = raw.get("model_id", raw.get("id", raw.get("modelId", "")))
    model_name = raw.get("model_name", raw.get("modelId", raw.get("name", "")))

    # License — check top-level first, then card_data
    license_id = raw.get("license", "") or card_data.get("license", "")

    # Pipeline tag
    pipeline_tag = raw.get("pipeline_tag", raw.get("task", "")) or ""

    # Author / publisher
    author = raw.get("author", raw.get("publisher", ""))
    publisher = raw.get("publisher", raw.get("author", ""))

    # Description — try card_data if top-level is empty
    description = raw.get("description", "") or card_data.get("description", "")

    # Tags
    tags = raw.get("tags", []) or []

    # Base model
    base_model_raw = card_data.get("base_model", "")
    base_model = (
        base_model_raw[0] if isinstance(base_model_raw, list) and base_model_raw
        else base_model_raw or ""
    )

    # Datasets — extract from card_data
    datasets = _extract_hf_datasets(card_data) if card_data else []

    # Metrics
    metrics = _extract_hf_metrics(card_data) if card_data else []

    # Modalities from card_data or inferred from pipeline_tag
    input_modalities = card_data.get("input_modalities", [])
    output_modalities = card_data.get("output_modalities", [])
    if not input_modalities or not output_modalities:
        _in, _out = _infer_modalities_from_pipeline(pipeline_tag)
        if not input_modalities:
            input_modalities = _in
        if not output_modalities:
            output_modalities = _out

    # Architecture inference
    merged_card = {**card_data, "config": raw.get("config", _raw_response.get("config", {}))}
    architecture_family = _infer_architecture_family(tags, merged_card)
    model_architecture = _infer_model_architecture(model_id, tags, merged_card)
    approach_type = _infer_approach_type(pipeline_tag, tags)

    # Considerations from README (if available in cache)
    readme = raw.get("readme_content", "")
    considerations = _extract_hf_considerations(readme) if readme else {}

    # Source URLs
    source_url = ""
    source_repo_url = ""
    if model_id and "/" in model_id:
        source_url = f"https://huggingface.co/{model_id}"
        source_repo_url = source_url

    # License URL
    license_url = f"https://huggingface.co/{model_id}/blob/main/LICENSE" if license_id else ""

    # Parameter count from safetensors
    safetensors = raw.get("safetensors", _raw_response.get("safetensors", {})) or {}
    parameter_count = int(safetensors["total"]) if safetensors.get("total") else 0
    parameter_dtype = ""
    if parameter_count:
        params = safetensors.get("parameters", {})
        if isinstance(params, dict) and params:
            parameter_dtype = next(iter(params))

    return NormalizedModelData(
        model_id=model_id,
        model_name=model_name,
        version=raw.get("version", raw.get("sha", "")),
        author=author,
        publisher=publisher,
        description=description,
        pipeline_tag=pipeline_tag,
        library_name=raw.get("library_name", ""),
        tags=tags,
        license_id=license_id,
        license_url=license_url,
        base_model=base_model,
        datasets=datasets,
        metrics=metrics,
        input_modalities=input_modalities,
        output_modalities=output_modalities,
        architecture_family=architecture_family,
        model_architecture=model_architecture,
        approach_type=approach_type,
        downloads=raw.get("downloads", 0),
        likes=raw.get("likes", 0),
        created_at=raw.get("created_at", raw.get("createdAt", "")),
        last_modified=raw.get("last_modified", raw.get("lastModified", "")),
        lookup_source=raw.get("_lookup_source", "cache"),
        source_url=source_url,
        source_repo_url=source_repo_url,
        parameter_count=parameter_count,
        parameter_dtype=parameter_dtype,
        intended_users=considerations.get("users", []),
        use_cases=considerations.get("use_cases", []),
        out_of_scope_use=considerations.get("out_of_scope_use", []),
        technical_limitations=considerations.get("limitations", []),
        ethical_considerations=considerations.get("ethical", []),
        fairness_assessments=considerations.get("fairness", []),
        performance_tradeoffs=considerations.get("performance_tradeoffs", []),
        environmental_considerations=considerations.get("environmental", {}),
        training_hardware=considerations.get("training_hardware", ""),
        inference_hardware=considerations.get("inference_hardware", ""),
        raw_metadata=raw,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# DEPRECATION LOGIC (absorbed from model_deprecation_checker)
# ═══════════════════════════════════════════════════════════════════════════════


class _DeprecationEngine:
    """
    O(1) deprecation checker — absorbed from ``model_deprecation_checker.py``.

    Loads provider JSON files from ``DEPRECATION_CACHE_DIR``, builds a
    normalized index, and provides single- and batch-check methods.
    Replacement chains are built lazily.
    """

    def __init__(self) -> None:
        self.deprecation_data: Dict[str, Dict] = {}
        self.model_index: Dict[str, Dict] = {}
        self.replacement_chains: Dict[str, Dict] = {}
        self._load_all_providers()
        self._build_model_index()

    def _load_all_providers(self) -> None:
        if not DEPRECATION_CACHE_DIR.exists():
            logger.warning(f"No deprecation cache directory: {DEPRECATION_CACHE_DIR}")
            return
        for json_file in DEPRECATION_CACHE_DIR.glob("*_deprecations.json"):
            provider = json_file.stem.replace("_deprecations", "").lower()
            try:
                self.deprecation_data[provider] = json.loads(
                    json_file.read_text(encoding="utf-8")
                )
            except Exception as exc:
                logger.error(f"Error loading {json_file}: {exc}")

    def _build_model_index(self) -> None:
        for provider, data in self.deprecation_data.items():
            for dep in data.get("deprecations", []):
                model_id = dep.get("model_or_system", "")
                if not model_id:
                    continue
                normalized = self._normalize(model_id)
                self.model_index[normalized] = {
                    "provider": provider,
                    "data": dep,
                    "original_id": model_id,
                }

    @staticmethod
    @lru_cache(maxsize=512)
    def _normalize(name: str) -> str:
        return name.replace("_", "-").lower()

    def _trace_chain(self, model_id: str, lookup: Dict) -> Dict:
        chain = [model_id]
        visited = {model_id}
        current = model_id
        for _ in range(DEPRECATION_MAX_CHAIN_DEPTH):
            dep_data = lookup.get(current)
            if not dep_data:
                break
            replacement = dep_data.get("recommended_replacement")
            if not replacement:
                break
            if " or " in replacement:
                replacement = replacement.split(" or ")[0].strip()
            if replacement not in lookup:
                chain.append(replacement)
                return {"chain": chain, "final_replacement": replacement, "depth": len(chain) - 1}
            if replacement in visited:
                break
            chain.append(replacement)
            visited.add(replacement)
            current = replacement
        return {
            "chain": chain,
            "final_replacement": chain[-1] if len(chain) > 1 else None,
            "depth": len(chain) - 1,
        }

    def _get_chain(self, model_id: str, provider: str) -> Dict:
        key = f"{provider}:{model_id}"
        if key in self.replacement_chains:
            return self.replacement_chains[key]
        lookup = {
            d.get("model_or_system", ""): d
            for d in self.deprecation_data.get(provider, {}).get("deprecations", [])
        }
        chain = self._trace_chain(model_id, lookup)
        self.replacement_chains[key] = chain
        return chain

    @staticmethod
    def _days_until_shutdown(dep: Dict) -> Optional[int]:
        sd = dep.get("shutdown_date")
        if not sd:
            return None
        try:
            return (datetime.strptime(sd, "%Y-%m-%d") - datetime.now()).days
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _severity(status: str, days: Optional[int]) -> str:
        if status == "shutdown":
            return "CRITICAL"
        if status == "deprecated":
            if days is not None:
                if days <= DEPRECATION_SEVERITY_THRESHOLDS["CRITICAL"]:
                    return "CRITICAL"
                if days <= DEPRECATION_SEVERITY_THRESHOLDS["HIGH"]:
                    return "HIGH"
                if days <= DEPRECATION_SEVERITY_THRESHOLDS["MEDIUM"]:
                    return "MEDIUM"
            return "HIGH"
        if status == "legacy":
            return "LOW"
        return "INFO"

    def check(self, model_name: str, provider: Optional[str] = None) -> Optional[DeprecationResult]:
        normalized = self._normalize(model_name)
        indexed = self.model_index.get(normalized)
        if not indexed:
            return None
        if provider and indexed["provider"] != provider.lower():
            return None
        dep = indexed["data"]
        prov = indexed["provider"]
        status = dep.get("status", "").lower()
        if status not in DEPRECATED_STATUSES:
            return None
        chain = self._get_chain(indexed["original_id"], prov)
        days = self._days_until_shutdown(dep)
        return DeprecationResult(
            model_name=model_name,
            deprecation_found=True,
            model_id=dep.get("model_or_system", ""),
            provider=prov,
            status=status,
            is_deprecated=True,
            severity=self._severity(status, days),
            announcement_date=dep.get("announcement_date"),
            shutdown_date=dep.get("shutdown_date"),
            days_until_shutdown=days,
            recommended_replacement=dep.get("recommended_replacement"),
            final_replacement=chain.get("final_replacement"),
            replacement_chain=chain.get("chain", []),
            category=dep.get("category"),
            dep_type=dep.get("type"),
            notes=dep.get("notes", ""),
        )

    def check_batch(self, model_names: List[str]) -> Dict[str, Any]:
        results: List[Dict] = []
        deprecated_count = 0
        shutdown_count = 0
        severity_breakdown: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
        }
        for name in model_names:
            dr = self.check(name)
            if dr:
                deprecated_count += 1
                if dr.status == "shutdown":
                    shutdown_count += 1
                severity_breakdown[dr.severity] = severity_breakdown.get(dr.severity, 0) + 1
                results.append({
                    "model_name": name,
                    "deprecation_found": True,
                    "deprecation_info": {
                        "model_id": dr.model_id, "provider": dr.provider,
                        "status": dr.status, "is_deprecated": dr.is_deprecated,
                        "severity": dr.severity,
                        "announcement_date": dr.announcement_date,
                        "shutdown_date": dr.shutdown_date,
                        "days_until_shutdown": dr.days_until_shutdown,
                        "recommended_replacement": dr.recommended_replacement,
                        "final_replacement": dr.final_replacement,
                        "replacement_chain": dr.replacement_chain,
                        "category": dr.category, "type": dr.dep_type,
                        "notes": dr.notes,
                    },
                })
            else:
                results.append({"model_name": name, "deprecation_found": False, "deprecation_info": None})

        return {
            "models_checked": len(model_names),
            "deprecated_count": deprecated_count,
            "shutdown_count": shutdown_count,
            "active_count": len(model_names) - deprecated_count,
            "severity_breakdown": severity_breakdown,
            "results": results,
        }


@lru_cache(maxsize=1)
def _get_deprecation_engine() -> _DeprecationEngine:
    return _DeprecationEngine()



# ═══════════════════════════════════════════════════════════════════════════════
# AIBOM ASSEMBLY — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════


# Global registry instance — connectors auto-registered at module load
connector_registry = ConnectorRegistry()


def _register_default_connectors() -> None:
    """Register built-in connectors.

    Only ModelCache (local O(1) lookups) and HuggingFace Hub are active.
    For models not found on HuggingFace, a note is added directing users
    to the respective model provider's page for model card details.
    """
    connector_registry.register(ModelCacheConnector())
    connector_registry.register(HuggingFaceConnector())


_register_default_connectors()


def _build_cdx_model_component(
    model_name: str, nd: NormalizedModelData, dep: Optional[DeprecationResult],
    ai_tag: str = "",
    evidence: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Build a single CycloneDX-ready component dict for one model.

    Follows CycloneDX 1.5+ component schema with ``modelCard`` sub-object,
    plus extended fields for hardware, lifecycle, and deprecation.
    The component ``type`` is derived dynamically from the AI scan tag.
    """
    # Map AI scan tags to descriptive component types
    TAG_TO_CDX_TYPE = {
        "LLM": "large-language-model",
        "DL":  "deep-learning-model",
        "ML":  "machine-learning-model",
        "AI":  "ai-model",
    }
    _component_type = TAG_TO_CDX_TYPE.get(ai_tag.upper(), "machine-learning-model") if ai_tag else "machine-learning-model"
    # Determine purl scheme based on model origin
    purl = ""
    if nd.model_id:
        # Check if a known hosting provider prefix is in model_id
        _purl_provider = nd.model_id.split("/")[0].lower() if "/" in nd.model_id else ""
        if _purl_provider in PROVIDER_CANONICAL_MAP:
            purl = f"pkg:{_purl_provider}/{nd.model_id.split('/', 1)[1]}"
        else:
            purl = f"pkg:huggingface/{nd.model_id}"

    # Build description — use tag-based fallback when connector found nothing
    _desc = nd.description or ""
    # Strip HTML comment placeholders from description
    _desc = re.sub(r'<!--.*?-->', '', _desc, flags=re.DOTALL).strip()
    _desc = re.sub(r'\[More Information Needed\]', '', _desc, flags=re.IGNORECASE).strip()
    if not _desc:
        if nd.lookup_source == "not_found":
            # Extract provider prefix for the redirect message
            _provider = model_name.split('/')[0] if '/' in model_name else 'the model provider'
            _desc = (
                f"Model card not found on HuggingFace. "
                f"For model card details, please refer to the {_provider} website "
                f"or the respective model provider's page for '{model_name}'."
            )
        elif ai_tag:
            _desc = f"{ai_tag} model detected in codebase"
        else:
            _desc = "AI model detected in codebase"

    component: Dict[str, Any] = {
        "type": _component_type,
        "bom-ref": f"model-{uuid.uuid4()}",
        "author": nd.author or nd.publisher or "",
        "name": nd.model_name or model_name,
        "version": nd.version,
        "description": _desc,
        "publisher": nd.publisher or nd.author,
        "purl": purl,
    }

    # Licenses
    if nd.license_id:
        component["licenses"] = [{"license": {"id": nd.license_id}}]

    # External references (with comment field per CycloneDX AIBOM spec)
    ext_refs: List[Dict] = []
    if nd.source_url:
        ext_refs.append({"comment": "Source URL", "type": "website", "url": nd.source_url})
    if nd.source_repo_url:
        ext_refs.append({"comment": "Source Repository", "type": "vcs", "url": nd.source_repo_url})
    if nd.license_url:
        ext_refs.append({"comment": "License", "type": "license", "url": nd.license_url})
    # Extract contact email from raw_metadata if available
    _contact = (nd.raw_metadata or {}).get("contact_email", "")
    if not _contact:
        # Try card_data for common contact patterns
        _card = (nd.raw_metadata or {}).get("card_data", {})
        if isinstance(_card, dict):
            _contact = _card.get("contact", _card.get("email", ""))
    if _contact:
        ext_refs.append({"comment": "Contact", "type": "email", "url": _contact})
    if ext_refs:
        component["externalReferences"] = ext_refs

    # Tags
    if nd.tags:
        component["tags"] = nd.tags[:50]

    # Properties (extra metadata as CycloneDX key-value pairs)
    properties: List[Dict[str, str]] = []
    # AI scan tag — preserves the classification from ai-targeted-scan
    # (LLM / ML / DL / AI) alongside the CycloneDX-required type
    if ai_tag:
        properties.append({"name": "ai:model:tag", "value": ai_tag})
    # Data source — shows where model card data was fetched from
    if nd.lookup_source:
        properties.append({"name": "ai:lookup:source", "value": nd.lookup_source})
    # Core AIBOM properties matching sample format
    if nd.pipeline_tag:
        properties.append({"name": "category", "value": nd.pipeline_tag})
    if nd.base_model:
        properties.append({"name": "baseModel", "value": nd.base_model})
        # Derive base model source URL
        _base_source = ""
        if "/" in nd.base_model:
            _base_source = f"https://huggingface.co/{nd.base_model}"
        elif nd.base_model:
            _base_source = f"https://huggingface.co/{nd.base_model}"
        if _base_source:
            properties.append({"name": "baseModelSource", "value": _base_source})
    # Filter out placeholder text from use_cases and out_of_scope_use
    _clean_uses = [u for u in (nd.use_cases or []) if not re.search(r'<!--.*?-->', u) and '[More Information Needed]' not in u]
    _clean_oos = [u for u in (nd.out_of_scope_use or []) if not re.search(r'<!--.*?-->', u) and '[More Information Needed]' not in u]
    if _clean_uses:
        properties.append({"name": "intendedUse", "value": "; ".join(_clean_uses)})
    if _clean_oos:
        properties.append({"name": "outOfScopeUse", "value": "; ".join(_clean_oos)})
    # Extended properties
    if nd.library_name:
        properties.append({"name": "library_name", "value": nd.library_name})
    if nd.context_window:
        properties.append({"name": "context_window", "value": str(nd.context_window)})
    if nd.max_output_tokens:
        properties.append({"name": "max_output_tokens", "value": str(nd.max_output_tokens)})
    if nd.knowledge_cutoff:
        properties.append({"name": "knowledge_cutoff", "value": nd.knowledge_cutoff})
    if nd.parameter_count:
        properties.append({"name": "parameter_count", "value": str(nd.parameter_count)})
    if nd.parameter_dtype:
        properties.append({"name": "parameter_dtype", "value": nd.parameter_dtype})
    if nd.downloads:
        properties.append({"name": "downloads", "value": str(nd.downloads)})
    if nd.likes:
        properties.append({"name": "likes", "value": str(nd.likes)})
    if nd.created_at:
        properties.append({"name": "created_at", "value": nd.created_at})
    if nd.last_modified:
        properties.append({"name": "last_modified", "value": nd.last_modified})
    # Provider overlay properties (dynamically from whatever the API returned)
    overlay = (nd.raw_metadata or {}).get("provider_overlay", {})
    for key, val in overlay.items():
        if val is not None and not isinstance(val, (dict, list)):
            properties.append({"name": key, "value": str(val)})
    # Detection evidence — source locations where this model was found in code
    for ev in (evidence or []):
        if ev.get("file"):
            properties.append({"name": "ai:evidence:file", "value": ev["file"]})
        if ev.get("line"):
            properties.append({"name": "ai:evidence:line", "value": str(ev["line"])})
        if ev.get("snippet"):
            properties.append({"name": "ai:evidence:snippet", "value": ev["snippet"]})
    if properties:
        component["properties"] = properties


    # ── modelCard ───────────────────────────────────────────────────────────
    model_card: Dict[str, Any] = {}

    # modelParameters
    model_params: Dict[str, Any] = {}
    if nd.approach_type:
        model_params["approach"] = {"type": nd.approach_type}
    if nd.pipeline_tag:
        model_params["task"] = nd.pipeline_tag
    if nd.architecture_family:
        model_params["architectureFamily"] = nd.architecture_family
    if nd.model_architecture:
        model_params["modelArchitecture"] = nd.model_architecture
    if nd.input_modalities:
        model_params["inputs"] = [{"format": m} for m in nd.input_modalities]
    if nd.output_modalities:
        model_params["outputs"] = [{"format": m} for m in nd.output_modalities]
    if nd.datasets:
        model_params["datasets"] = [
            {
                "name": ds.name,
                "type": ds.dataset_type,
                "description": ds.description,
                "classification": ds.classification,
                **({"sensitiveData": ds.sensitive_data} if ds.sensitive_data else {}),
                **({"governance": ds.governance} if ds.governance else {}),
                **({"contents": {"url": ds.url}} if ds.url else {}),
            }
            for ds in nd.datasets
        ]
    if model_params:
        model_card["modelParameters"] = model_params


    # considerations — strip placeholder text before including
    def _strip_placeholders(text):
        """Remove HTML comments and [More Information Needed] from text."""
        if isinstance(text, str):
            cleaned = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL).strip()
            cleaned = re.sub(r'\[More Information Needed\]', '', cleaned, flags=re.IGNORECASE).strip()
            return cleaned if len(cleaned) > 10 else ""
        if isinstance(text, dict):
            if "description" in text:
                cleaned = _strip_placeholders(text["description"])
                if cleaned:
                    return {**text, "description": cleaned}
                return None
            if "name" in text:
                cleaned = _strip_placeholders(text["name"])
                if cleaned:
                    return {**text, "name": cleaned}
                return None
        return text

    def _clean_list(items):
        """Filter out placeholder entries from a list."""
        result = []
        for item in (items or []):
            if isinstance(item, str):
                cleaned = _strip_placeholders(item)
                if cleaned:
                    result.append(cleaned)
            elif isinstance(item, dict):
                cleaned = _strip_placeholders(item)
                if cleaned:
                    result.append(cleaned)
        return result

    considerations: Dict[str, Any] = {}
    _cleaned_users = _clean_list(nd.intended_users)
    if _cleaned_users:
        considerations["users"] = _cleaned_users
    _cleaned_uses = _clean_list(nd.use_cases)
    if _cleaned_uses:
        considerations["useCases"] = _cleaned_uses
    _cleaned_limits = _clean_list(nd.technical_limitations)
    if _cleaned_limits:
        considerations["technicalLimitations"] = _cleaned_limits
    _cleaned_perf = _clean_list(nd.performance_tradeoffs)
    if _cleaned_perf:
        considerations["performanceTradeoffs"] = _cleaned_perf
    _cleaned_ethical = _clean_list(nd.ethical_considerations)
    if _cleaned_ethical:
        considerations["ethicalConsiderations"] = _cleaned_ethical
    _cleaned_fairness = _clean_list(nd.fairness_assessments)
    if _cleaned_fairness:
        considerations["fairnessAssessments"] = _cleaned_fairness
    if nd.environmental_considerations:
        _env_cleaned = _strip_placeholders(nd.environmental_considerations)
        if _env_cleaned:
            considerations["environmentalConsiderations"] = _env_cleaned
    if considerations:
        model_card["considerations"] = considerations

    # hardware — strip placeholder text
    hardware: Dict[str, str] = {}
    if nd.training_hardware:
        _hw = _strip_placeholders(nd.training_hardware)
        if _hw:
            hardware["training"] = _hw
    if nd.inference_hardware:
        _hw = _strip_placeholders(nd.inference_hardware)
        if _hw:
            hardware["inference"] = _hw
    if hardware:
        model_card["hardware"] = hardware

    if model_card:
        component["modelCard"] = model_card

    # ── Lifecycle / Deprecation ─────────────────────────────────────────────
    if dep and dep.deprecation_found:
        component["lifecycleStatus"] = dep.status
        component["deprecationStatus"] = dep.status
        component["deprecationSeverity"] = dep.severity
        if dep.shutdown_date:
            component["shutdownDate"] = dep.shutdown_date
        if dep.recommended_replacement or dep.final_replacement:
            component["replacementModel"] = dep.final_replacement or dep.recommended_replacement
        if dep.notes:
            component["deprecationNotice"] = dep.notes
        if dep.replacement_chain:
            component["_deprecation"] = {
                "replacement_chain": dep.replacement_chain,
                "days_until_shutdown": dep.days_until_shutdown,
            }

    return component


def _build_cdx_vulnerabilities(
    deprecation_results: List[DeprecationResult],
) -> List[Dict[str, Any]]:
    """Build CycloneDX ``vulnerabilities[]`` from deprecation data."""
    vulns: List[Dict[str, Any]] = []
    for dep in deprecation_results:
        if not dep.deprecation_found:
            continue
        vuln: Dict[str, Any] = {
            "id": f"AIBOM-DEP-{dep.model_id}",
            "source": {"name": "AIBOM Deprecation Checker", "url": ""},
            "description": (
                f"Model {dep.model_id} is {dep.status} by {dep.provider}. "
                f"{dep.notes}"
            ).strip(),
            "recommendation": (
                f"Migrate to {dep.final_replacement or dep.recommended_replacement}"
                if dep.recommended_replacement
                else "Review model status and find an active replacement."
            ),
            "analysis": {
                "state": "exploitable" if dep.status == "shutdown" else "in_triage",
            },
            "ratings": [
                {
                    "severity": dep.severity.lower(),
                    "method": "other",
                    "source": {"name": "AIBOM"},
                }
            ],
        }
        if dep.shutdown_date:
            vuln["properties"] = [
                {"name": "shutdown_date", "value": dep.shutdown_date},
                {"name": "days_until_shutdown", "value": str(dep.days_until_shutdown or "")},
            ]
        if dep.replacement_chain:
            vuln["properties"] = vuln.get("properties", []) + [
                {"name": "replacement_chain", "value": " → ".join(dep.replacement_chain)}
            ]
        vulns.append(vuln)
    return vulns


def build_aibom(
    session_extra: Dict[str, Any],
    hf_token: Optional[str] = None,
    tool_name: str = "PrismAIBOM",
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """
    Main entry point — build the complete AIBOM connector output.

    Reads ``distinct_models`` from ``session.extra["ai_targeted_scan"]``,
    resolves each model through the ``ConnectorRegistry`` (with suffix
    stripping), checks deprecation, pulls agentic frameworks from session,
    and assembles a CycloneDX-ready structure.

    Returns a dict suitable for direct JSON serialization and storage
    in ``session.extra["aibom_connector"]``.
    """
    # ── 1. Gather distinct models ───────────────────────────────────────────
    ai_scan = session_extra.get("ai_targeted_scan", {})
    distinct_models: List[str] = ai_scan.get("distinct_models", [])

    # Build evidence map: model_name → list of {file, line, snippet} from scan findings.
    # Primary source: model_detection_findings (have code_snippet).
    # Fallback: models_detected (provider-level inferred entries that lack a finding).
    _evidence_map: Dict[str, List[Dict[str, Any]]] = {}
    for _f in ai_scan.get("model_detection_findings", []):
        _mv = _f.get("model_value", "")
        if not _mv:
            continue
        _evidence_map.setdefault(_mv, []).append({
            "file": _f.get("file", ""),
            "line": _f.get("line", 0),
            "snippet": (_f.get("code_snippet") or "").strip(),
        })
    for _md in ai_scan.get("models_detected", []):
        _mv = _md.get("model", "")
        if _mv and _mv not in _evidence_map and _md.get("file"):
            _evidence_map[_mv] = [{
                "file": _md.get("file", ""),
                "line": _md.get("line", 0),
                "snippet": "",
            }]

    # ── 2. Resolve each model via connector registry ────────────────────────
    components: List[Dict[str, Any]] = []
    model_results: List[Dict[str, Any]] = []
    all_deprecations: List[DeprecationResult] = []
    deprecation_engine = _get_deprecation_engine()

    cache_connector: Optional[ModelCacheConnector] = None
    for c in connector_registry._connectors:
        if isinstance(c, ModelCacheConnector):
            cache_connector = c
            break

    for model_name in distinct_models:
        # 2a. Resolve metadata (waterfall with provider remap + suffix stripping)
        original_model_name = model_name
        nd = connector_registry.resolve(
            model_name, hf_token=hf_token, session_extra=session_extra
        )

        suffix_info: List[Dict] = []
        stripped_suffixes: List[str] = []
        base_name = model_name
        remapped_to: str = ""

        if nd is None:
            # Try provider prefix remapping (e.g. groq/llama → meta-llama/Llama)
            canonical_id = remap_provider_model(model_name)
            if canonical_id:
                remapped_to = canonical_id
                nd = connector_registry.resolve(
                    canonical_id, hf_token=hf_token, session_extra=session_extra
                )
                if nd is not None:
                    # Preserve original model name in the output
                    nd.model_name = model_name
                    nd.lookup_source = f"{nd.lookup_source}_remapped"

        if nd is None:
            # Try HuggingFace search API fallback
            search_id = _hf_search_fallback(model_name)
            if search_id:
                remapped_to = search_id
                nd = connector_registry.resolve(
                    search_id, hf_token=hf_token, session_extra=session_extra
                )
                if nd is not None:
                    nd.model_name = model_name
                    nd.lookup_source = f"{nd.lookup_source}_searched"

        if nd is None:
            # Try suffix stripping
            for stripped_name, removed in strip_model_name_incrementally(model_name):
                nd = connector_registry.resolve(
                    stripped_name, hf_token=hf_token, session_extra=session_extra
                )
                if nd is not None:
                    base_name = stripped_name
                    stripped_suffixes = removed
                    suffix_info = [parse_suffix(s) for s in removed]
                    nd.lookup_source = f"{nd.lookup_source}_stripped"
                    break

            # If suffix stripping didn't work, try remap + strip combo
            if nd is None and "/" in model_name:
                provider = model_name.split("/")[0]
                model_part = model_name.split("/", 1)[1]
                for stripped_name, removed in strip_model_name_incrementally(model_part):
                    # Try remapping the stripped version
                    remap_key = f"{provider}/{stripped_name}"
                    canonical_id = remap_provider_model(remap_key)
                    if canonical_id:
                        nd = connector_registry.resolve(
                            canonical_id, hf_token=hf_token, session_extra=session_extra
                        )
                        if nd is not None:
                            remapped_to = canonical_id
                            nd.model_name = model_name
                            nd.lookup_source = f"{nd.lookup_source}_remapped_stripped"
                            stripped_suffixes = removed
                            suffix_info = [parse_suffix(s) for s in removed]
                            break

        # If still nothing, create a minimal entry
        if nd is None:
            full_suffix = extract_suffix_info(model_name)
            if full_suffix.get("has_suffixes"):
                suffix_info = full_suffix.get("parsed_suffixes", [])
            nd = NormalizedModelData(
                model_id=model_name,
                model_name=model_name,
                lookup_source="not_found",
                description=(
                    f"Model card not found on HuggingFace. "
                    f"For model card details, please refer to the respective "
                    f"model provider's page for '{model_name}'."
                ),
            )

        # 2a-extra. Apply provider-specific overlay for hosted variants
        # (e.g. Groq's context_window, description, speed for "versatile")
        if "/" in original_model_name and nd.lookup_source != "not_found":
            prov = original_model_name.split("/")[0]
            mpart = original_model_name.split("/", 1)[1]
            # Store the canonical base-model ID so the overlay can tag it
            if remapped_to:
                if not nd.raw_metadata:
                    nd.raw_metadata = {}
                nd.raw_metadata["_canonical_id"] = remapped_to
            _apply_provider_overlay(nd, prov, mpart)

        # 2a-upstream. Fetch upstream MODEL_CARD.md from GitHub to fill gaps
        # (considerations, benchmarks, hardware, description, knowledge cutoff)
        # Uses the canonical HF ID (or the model_id itself) to locate the
        # correct upstream repo.
        _upstream_target = remapped_to or nd.raw_metadata.get("_canonical_id", "") if nd.raw_metadata else ""
        if not _upstream_target and nd.model_id:
            _upstream_target = nd.model_id
        if _upstream_target and nd.lookup_source != "not_found":
            # Only fetch if we're still missing key fields
            _needs_upstream = (
                not nd.intended_users
                and not nd.use_cases
                and not nd.technical_limitations
                and not nd.metrics
            )
            if _needs_upstream:
                upstream_md = _fetch_upstream_model_card(_upstream_target)
                if upstream_md:
                    _merge_upstream_into_nd(nd, upstream_md)

        # 2b. Cache the resolved data for future use
        if cache_connector and nd.lookup_source not in ("not_found", "cache", "local_aibom_cache"):
            cache_connector.save(
                model_name,
                nd.raw_metadata or {"model_id": nd.model_id, "model_name": nd.model_name},
                source=nd.lookup_source,
            )

        # 2c. Check deprecation
        dep_result = deprecation_engine.check(model_name)
        if dep_result:
            all_deprecations.append(dep_result)

        # 2d. Build CycloneDX component — pass AI tag and detection evidence
        _all_models_tags = ai_scan.get("all_models", [])
        _model_tag = ""
        for _mt in _all_models_tags:
            _mname = _mt.get("model_name", _mt.get("model", ""))
            if _mname == model_name:
                _model_tag = _mt.get("tag", "AI")
                break
        component = _build_cdx_model_component(
            model_name, nd, dep_result,
            ai_tag=_model_tag,
            evidence=_evidence_map.get(model_name),
        )
        components.append(component)

        # 2e. Track per-model result
        model_results.append({
            "model_name": model_name,
            "base_model_name": base_name,
            "remapped_to": remapped_to,
            "model_card_found": nd.lookup_source != "not_found",
            "lookup_source": nd.lookup_source,
            "stripped_suffixes": stripped_suffixes,
            "suffix_info": suffix_info,
            "connector_used": nd.lookup_source.split("_stripped")[0].split("_remapped")[0].split("_searched")[0] if nd.lookup_source else "",
        })

    # ── 3. Deprecation summary ──────────────────────────────────────────────
    deprecated_count = sum(1 for d in all_deprecations if d.deprecation_found)
    shutdown_count = sum(1 for d in all_deprecations if d.status == "shutdown")
    severity_breakdown: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for d in all_deprecations:
        severity_breakdown[d.severity] = severity_breakdown.get(d.severity, 0) + 1

    deprecation_summary = {
        "models_checked": len(distinct_models),
        "deprecated_count": deprecated_count,
        "shutdown_count": shutdown_count,
        "active_count": len(distinct_models) - deprecated_count,
        "severity_breakdown": severity_breakdown,
    }

    # ── 4. Vulnerabilities from deprecation ─────────────────────────────────
    vulnerabilities = _build_cdx_vulnerabilities(all_deprecations)

    # ── 5. Library components from AI categorization ────────────────────────
    # Inject AI framework libraries (e.g. PyTorch, Transformers) as separate
    # type:library components and link them via dependsOn to model components.
    library_components: List[Dict[str, Any]] = []
    library_bom_refs: List[str] = []
    llm_cat = session_extra.get("llm_categorization", {})
    # Also check llm_validation for the raw AI library list
    llm_val = session_extra.get("llm_validation", {})
    _seen_libs: set = set()

    # Collect libraries from categorization (ai_categories)
    for _cat_key, _cat_data in llm_cat.get("ai_categories", {}).items():
        for _lib in _cat_data.get("libraries", []):
            _lib_name = _lib.get("library", "") if isinstance(_lib, dict) else str(_lib)
            if not _lib_name or _lib_name.lower() in _seen_libs:
                continue
            _seen_libs.add(_lib_name.lower())
            _lib_ref = f"lib-{_lib_name.lower().replace(' ', '-').replace('.', '-')}"
            library_components.append({
                "type": "library",
                "bom-ref": _lib_ref,
                "name": _lib_name,
            })
            library_bom_refs.append(_lib_ref)

    # Also add from llm_validation ai_libraries if not already covered
    for _lib in llm_val.get("ai_libraries", []):
        _lib_name = _lib.get("library", "") if isinstance(_lib, dict) else str(_lib)
        if not _lib_name or _lib_name.lower() in _seen_libs:
            continue
        _seen_libs.add(_lib_name.lower())
        _lib_ref = f"lib-{_lib_name.lower().replace(' ', '-').replace('.', '-')}"
        library_components.append({
            "type": "library",
            "bom-ref": _lib_ref,
            "name": _lib_name,
        })
        library_bom_refs.append(_lib_ref)
    # ── 6. Assembly (CycloneDX-ready) ───────────────────────────────────────
    now = datetime.utcnow().isoformat() + "Z"
    source_counts: Dict[str, int] = {}
    for mr in model_results:
        src = mr.get("lookup_source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    # Derive top-level metadata fields from resolved components
    authors: List[Dict[str, str]] = []
    licenses_set: set = set()
    seen_authors: set = set()
    for comp in components:
        pub = comp.get("publisher", "")
        if pub and pub not in seen_authors:
            seen_authors.add(pub)
            authors.append({"name": pub})
        for lic_entry in comp.get("licenses", []):
            lid = lic_entry.get("license", {}).get("id", "")
            if lid:
                licenses_set.add(lid)

    metadata_block: Dict[str, Any] = {
        "timestamp": now,
        "tools": [{"name": tool_name, "version": tool_version}],
    }
    # metadata.component: describe the primary model if models exist,
    # otherwise describe the tool itself (per CycloneDX AIBOM spec).
    # Pick the best model (one with a description/modelCard) instead of
    # blindly using the first component which may be a not_found model.
    if components:
        # Prefer a component that has a modelCard or non-empty description
        _primary = components[0]
        for _c in components:
            # Skip library components
            if _c.get("type") == "library":
                continue
            if _c.get("modelCard") or _c.get("description"):
                _primary = _c
                break

        # Build a meaningful description — include the AI tag if available
        _all_models_tags = ai_scan.get("all_models", [])
        _tag_map = {}
        for _mt in _all_models_tags:
            _mname = _mt.get("model_name", _mt.get("model", ""))
            _tag = _mt.get("tag", "AI")
            if _mname:
                _tag_map[_mname] = _tag

        _prim_name = _primary.get("name", "")
        _prim_desc = _primary.get("description", "")
        _prim_tag = _tag_map.get(_prim_name, "")

        # If no description was found, build one from the name + tag
        if not _prim_desc and _prim_tag:
            _prim_desc = f"{_prim_tag} model detected in codebase"
        elif not _prim_desc:
            _prim_desc = f"AI model detected in codebase"

        _meta_component: Dict[str, Any] = {
            "type": _primary.get("type", "machine-learning-model"),
            "name": _prim_name,
            "description": _prim_desc,
        }
        # Carry over author from primary component
        _prim_author = _primary.get("author", "")
        if _prim_author:
            _meta_component["author"] = _prim_author
        # Carry over licenses from primary component
        _prim_licenses = _primary.get("licenses", [])
        if _prim_licenses:
            _meta_component["licenses"] = _prim_licenses
        metadata_block["component"] = _meta_component
    else:
        metadata_block["component"] = {
            "type": "application",
            "name": tool_name,
            "version": tool_version,
            "description": "AI Bill of Materials generator — CycloneDX 1.5",
        }
    if authors:
        metadata_block["authors"] = authors
        metadata_block["supplier"] = authors[0]  # primary supplier = first author
    if licenses_set:
        metadata_block["licenses"] = [{"license": {"id": lid}} for lid in sorted(licenses_set)]

    # Build dependsOn — link model components to library components
    _model_types = {"machine-learning-model", "large-language-model", "deep-learning-model", "ai-model"}
    dependencies: List[Dict[str, Any]] = []
    for comp in components:
        dep_entry: Dict[str, Any] = {"ref": comp["bom-ref"]}
        # Link each model component to all library components via dependsOn
        if library_bom_refs and comp.get("type") in _model_types:
            dep_entry["dependsOn"] = list(library_bom_refs)
        dependencies.append(dep_entry)
    # Add library components themselves (no dependsOn)
    for lib_comp in library_components:
        dependencies.append({"ref": lib_comp["bom-ref"]})

    # Merge library components into the main components list
    all_components = components + library_components

    # Compositions
    compositions: List[Dict[str, Any]] = []
    if components:
        found_refs = [c["bom-ref"] for c in components if c.get("modelCard")]
        not_found_refs = [c["bom-ref"] for c in components if not c.get("modelCard")]
        if found_refs:
            compositions.append({"aggregate": "complete", "assemblies": found_refs})
        if not_found_refs:
            compositions.append({"aggregate": "incomplete", "assemblies": not_found_refs})

    aibom: Dict[str, Any] = {
        # ── Core identifiers ────────────────────────────────────────────────
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": metadata_block,
        # ── Components (models + libraries) ─────────────────────────────────
        "components": all_components,
        # ── Dependencies ────────────────────────────────────────────────────
        "dependencies": dependencies,
        # ── Compositions ────────────────────────────────────────────────────
        "compositions": compositions,
        # ── Vulnerabilities (deprecation) ───────────────────────────────────
        "vulnerabilities": vulnerabilities,

        # ── Connector metadata (non-CycloneDX, for internal tracking) ──────
        "_connector_meta": {
            "models_processed": len(distinct_models),
            "models_found": sum(1 for mr in model_results if mr["model_card_found"]),
            "models_not_found": sum(1 for mr in model_results if not mr["model_card_found"]),
            "model_results": model_results,
            "source_breakdown": source_counts,
            "success_rate": (
                f"{sum(1 for mr in model_results if mr['model_card_found']) / len(model_results) * 100:.1f}%"
                if model_results
                else "0%"
            ),
            "deprecation_summary": deprecation_summary,
        },
    }

    return aibom


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

__all__ = [
    # Data structures
    "NormalizedModelData",
    "DatasetInfo",
    "MetricInfo",
    "DeprecationResult",
    "AgenticFrameworkEntry",
    # Base class
    "BaseModelConnector",
    # Registry
    "ConnectorRegistry",
    "connector_registry",
    # Implemented connectors
    "ModelCacheConnector",
    "HuggingFaceConnector",
    "ReplicateConnector",
    "AzureAICatalogConnector",
    "TFHubConnector",
    "ONNXModelZooConnector",
    "GitRepoConnector",
    # Stub connectors
    "PyTorchHubConnector",
    "KaggleConnector",
    "MLflowConnector",
    "SageMakerConnector",
    "AzureMLConnector",
    "VertexAIConnector",
    "WandBConnector",
    "OCIRegistryConnector",
    # Main entry
    "build_aibom",
]

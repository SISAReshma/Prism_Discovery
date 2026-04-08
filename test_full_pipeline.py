"""Integration test: verify the full resolution pipeline for groq/llama-3.3-70b-versatile."""
import sys, os, json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path("aibom/src/.env"), override=False)

sys.path.insert(0, "aibom/src")
sys.path.insert(0, ".")

from aibom_connector import (
    connector_registry,
    remap_provider_model,
    _apply_provider_overlay,
    _fetch_upstream_model_card,
    _merge_upstream_into_nd,
    _resolve_upstream_model_card_url,
    _build_cdx_model_component,
)

token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
print(f"Token available: {bool(token)}")

model = "groq/llama-3.3-70b-versatile"
print(f"\n=== Resolving: {model} ===")

# Step 1: Direct resolve (will fail — Groq prefix)
nd = connector_registry.resolve(model, hf_token=token)
print(f"1. Direct resolve: {'found' if nd else 'None'}")

# Step 2: Remap
canonical_id = remap_provider_model(model)
print(f"2. Remap: {canonical_id}")

# Step 3: Resolve canonical
if canonical_id:
    nd = connector_registry.resolve(canonical_id, hf_token=token)
    print(f"3. Resolve canonical: {nd.lookup_source if nd else 'None'}")

if nd:
    # Step 4: Apply provider overlay
    nd.raw_metadata["_canonical_id"] = canonical_id
    _apply_provider_overlay(nd, "groq", "llama-3.3-70b-versatile")
    print(f"4. After overlay:")
    print(f"   model_id: {nd.model_id}")
    print(f"   source_url: {nd.source_url}")
    print(f"   context_window: {nd.context_window}")
    print(f"   description[:80]: {(nd.description or '')[:80]}")

    # Step 5: Upstream model card
    print(f"\n5. Upstream model card:")
    url = _resolve_upstream_model_card_url(canonical_id)
    print(f"   URL: {url}")
    upstream_md = _fetch_upstream_model_card(canonical_id)
    print(f"   Length: {len(upstream_md)} chars")

    if upstream_md:
        _merge_upstream_into_nd(nd, upstream_md)
        print(f"\n6. After merge:")
        print(f"   intended_users: {nd.intended_users[:2]}")
        print(f"   use_cases: {nd.use_cases[:2]}")
        print(f"   technical_limitations: {nd.technical_limitations[:2]}")
        print(f"   ethical_considerations: {nd.ethical_considerations[:2]}")
        print(f"   training_hardware: {nd.training_hardware[:80]}")
        print(f"   environmental: {nd.environmental_considerations}")
        print(f"   knowledge_cutoff: {nd.knowledge_cutoff}")
        print(f"   metrics count: {len(nd.metrics)}")
        if nd.metrics:
            for m in nd.metrics[:5]:
                print(f"     - {m.slice_label}: {m.metric_type}={m.value}")

    # Step 6: Build CDX component
    comp = _build_cdx_model_component(model, nd, None)
    print(f"\n7. CycloneDX component:")
    print(f"   name: {comp.get('name')}")
    print(f"   purl: {comp.get('purl')}")
    print(f"   source_url: {[r.get('url') for r in comp.get('externalReferences', [])]}")

    mc = comp.get("modelCard", {})
    mp = mc.get("modelParameters", {})
    print(f"\n   modelCard.modelParameters:")
    print(f"     modelArchitecture: {mp.get('modelArchitecture')}")
    print(f"     architectureFamily: {mp.get('architectureFamily')}")
    print(f"     task: {mp.get('task')}")
    print(f"     inputs: {mp.get('inputs')}")
    print(f"     outputs: {mp.get('outputs')}")
    print(f"     datasets: {len(mp.get('datasets', []))}")

    qa = mc.get("quantitativeAnalysis", {})
    print(f"\n   modelCard.quantitativeAnalysis:")
    print(f"     performanceMetrics: {len(qa.get('performanceMetrics', []))}")

    cons = mc.get("considerations", {})
    print(f"\n   modelCard.considerations:")
    for k in ("users", "useCases", "technicalLimitations",
              "ethicalConsiderations", "environmentalConsiderations"):
        v = cons.get(k, [])
        print(f"     {k}: {len(v) if isinstance(v, list) else bool(v)}")

    hw = mc.get("hardware", {})
    print(f"\n   modelCard.hardware:")
    print(f"     training: {bool(hw.get('training'))}")
    print(f"     inference: {bool(hw.get('inference'))}")

    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    print(f"\n   properties:")
    print(f"     parameter_count: {props.get('parameter_count', 'N/A')}")
    print(f"     context_window: {props.get('context_window', 'N/A')}")
    print(f"     knowledge_cutoff: {props.get('knowledge_cutoff', 'N/A')}")

    tags = comp.get("tags", [])
    variant_tags = [t for t in tags if t.startswith("variant")]
    provider_tags = [t for t in tags if t.startswith("provider")]
    print(f"\n   tags: provider={provider_tags}, variant={variant_tags}")

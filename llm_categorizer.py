"""
LLM Categorizer for AI Library Classification
Categorizes AI-positive libraries into specific types using Groq LLM.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

from config import (
    LLM_BATCH_SIZE,
    LLM_MAX_TOKENS_PER_LIB,
    LLM_MAX_TOKENS_CAP,
    LLM_MIN_TOKENS,
    LLM_TEMPERATURE,
    LLM_CATEGORIZATION_PROMPT,
)

# Load environment variables
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

# Get LLM configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
LLM_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")

# Valid categories (uppercase for normalization)
VALID_CATEGORIES = {
    "AI_PROVIDER", "ML_ALGORITHM", "DL_ALGORITHM",
    "AI_ORCHESTRATION", "VECTOR_DB", "DATA_PROCESSING", "UNKNOWN"
}

# Initialize Groq client (lazy loading)
_groq_client = None


def get_groq_client():
    """Get or create Groq client."""
    global _groq_client
    if _groq_client is None:
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not set in environment")
        from groq import Groq
        _groq_client = Groq(api_key=GROQ_API_KEY)
    return _groq_client


def categorize_batch(ai_libraries: List[Dict]) -> List[Dict]:
    """
    Categorize a batch of AI libraries using LLM.
    
    Args:
        ai_libraries: List of AI library dicts with library name and source_files
        
    Returns:
        List of categorization results
    """
    if not ai_libraries:
        return []
    
    client = get_groq_client()
    
    # Build input with library names only (no source files in prompt for brevity)
    lib_names = [lib["library"] for lib in ai_libraries]
    lib_list = "\n".join([f"- {name}" for name in lib_names])
    
    messages = [
        {"role": "system", "content": LLM_CATEGORIZATION_PROMPT.strip()},
        {"role": "user", "content": f"Categorize these AI/ML libraries:\n{lib_list}"}
    ]
    
    # Calculate max tokens
    estimated_tokens = len(ai_libraries) * LLM_MAX_TOKENS_PER_LIB + 500
    max_tokens = max(LLM_MIN_TOKENS, min(estimated_tokens, LLM_MAX_TOKENS_CAP))
    
    try:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=LLM_TEMPERATURE,
            max_tokens=max_tokens
        )
        
        output_text = response.choices[0].message.content
        finish_reason = response.choices[0].finish_reason
        
        if finish_reason == "length":
            print(f"[llm_categorizer] Warning: Response truncated at {max_tokens} tokens")
        
        return parse_llm_response(output_text)
        
    except Exception as e:
        print(f"[llm_categorizer] Error calling LLM API: {e}")
        return []


def parse_llm_response(output_text: str) -> List[Dict]:
    """Extract JSON array from LLM response."""
    # Try markdown code block
    if "```json" in output_text:
        start = output_text.find("```json") + 7
        end = output_text.find("```", start)
        if end != -1:
            json_text = output_text[start:end].strip()
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                pass
    
    # Try generic code block
    if "```" in output_text:
        match = re.search(r'```\s*\n?(.*?)```', output_text, re.DOTALL)
        if match:
            json_text = match.group(1).strip()
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                pass
    
    # Try finding JSON array directly
    start = output_text.find("[")
    end = output_text.rfind("]")
    if start != -1 and end != -1:
        try:
            return json.loads(output_text[start:end+1])
        except json.JSONDecodeError as e:
            print(f"[llm_categorizer] JSON parse error: {e}")
            return []
    
    print("[llm_categorizer] Could not find JSON array in response")
    return []


def categorize_libraries(ai_libraries: List[Dict]) -> List[Dict]:
    """
    Categorize all AI libraries, batching if necessary.
    
    Args:
        ai_libraries: List of AI library dicts
        
    Returns:
        List of all categorization results
    """
    if not ai_libraries:
        return []
    
    # Deduplicate by library name
    seen = set()
    unique_libs = []
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        if lib_name and lib_name not in seen:
            seen.add(lib_name)
            unique_libs.append(lib)
    
    if len(unique_libs) <= LLM_BATCH_SIZE:
        return categorize_batch(unique_libs)
    
    # Process in batches
    all_results = []
    total_batches = (len(unique_libs) + LLM_BATCH_SIZE - 1) // LLM_BATCH_SIZE
    
    for i in range(0, len(unique_libs), LLM_BATCH_SIZE):
        batch = unique_libs[i:i + LLM_BATCH_SIZE]
        batch_num = (i // LLM_BATCH_SIZE) + 1
        print(f"[llm_categorizer] Processing batch {batch_num}/{total_batches} ({len(batch)} libraries)")
        
        batch_results = categorize_batch(batch)
        all_results.extend(batch_results)
    
    return all_results


def build_categorization_result(
    ai_libraries: List[Dict],
    categorizations: List[Dict]
) -> Dict:
    """
    Build the final categorization result with categories and counts.
    
    Args:
        ai_libraries: Original AI libraries with source files
        categorizations: LLM categorization results
        
    Returns:
        Structured categorization result
    """
    # Create lookup for categorizations (normalize library names)
    cat_map = {c.get("library", "").lower(): c for c in categorizations}
    
    # Initialize categories
    categories = {cat: [] for cat in VALID_CATEGORIES}
    
    # Categorize each library
    for lib in ai_libraries:
        lib_name = lib.get("library", "")
        
        entry = {
            "library": lib_name,
            "source_files": lib.get("source_files", []),
            "language": lib.get("language")
        }
        
        # Look up categorization (case-insensitive)
        cat_data = cat_map.get(lib_name.lower())
        
        if cat_data:
            # Normalize category to uppercase
            raw_category = cat_data.get("category", "UNKNOWN")
            category = raw_category.upper().replace(" ", "_")
            
            # Validate category exists
            if category not in VALID_CATEGORIES:
                category = "UNKNOWN"
            
            entry["confidence"] = cat_data.get("confidence", "LOW")
            entry["reason"] = cat_data.get("reason", "")
        else:
            category = "UNKNOWN"
            entry["confidence"] = "LOW"
            entry["reason"] = "Categorization failed"
        
        categories[category].append(entry)
    
    # Build response structure
    by_category = {}
    for cat_key, libs in categories.items():
        cat_name_lower = cat_key.lower()
        by_category[cat_name_lower] = {
            "count": len(libs),
            "libraries": libs
        }
    
    return {
        "by_category": by_category,
        "total_libraries": len(ai_libraries),
        "model_used": LLM_MODEL
    }


def _empty_categories() -> Dict:
    """Return empty category structure."""
    return {
        "by_category": {cat.lower(): {"count": 0, "libraries": []} for cat in VALID_CATEGORIES},
        "total_libraries": 0,
        "model_used": LLM_MODEL
    }


def run_categorization(ai_libraries: List[Dict]) -> Optional[Dict]:
    """
    Main categorization function.
    
    Args:
        ai_libraries: List of AI-positive libraries from /llm-validate
        
    Returns:
        Categorization result or None if failed
    """
    if not ai_libraries:
        return _empty_categories()
    
    print(f"[llm_categorizer] Categorizing {len(ai_libraries)} AI libraries...")
    
    # Categorize with LLM
    categorizations = categorize_libraries(ai_libraries)
    
    if not categorizations:
        return None
    
    # Build result
    result = build_categorization_result(ai_libraries, categorizations)
    
    return result

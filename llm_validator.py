"""
LLM Validator for AI Library Classification
Validates and classifies libraries as AI-positive or non-AI using Groq LLM.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

from dotenv import load_dotenv

from config import (
    LLM_BATCH_SIZE,
    LLM_MAX_TOKENS_PER_LIB,
    LLM_MAX_TOKENS_CAP,
    LLM_MIN_TOKENS,
    LLM_TEMPERATURE,
    LLM_SYSTEM_PROMPT,
)

# Load environment variables
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)

# Get LLM configuration from environment
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
LLM_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")  # Use GROQ_MODEL from .env

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


def classify_batch(libraries: List[str]) -> List[Dict]:
    """
    Classify a single batch of libraries using LLM.
    
    Args:
        libraries: List of library names to classify
        
    Returns:
        List of classification results
    """
    if not libraries:
        return []
    
    client = get_groq_client()
    
    # Build library list for prompt
    lib_list = "\n".join([f"- {lib}" for lib in libraries])
    
    messages = [
        {"role": "system", "content": LLM_SYSTEM_PROMPT.strip()},
        {"role": "user", "content": f"Classify these libraries:\n{lib_list}"}
    ]
    
    # Calculate max tokens based on library count
    estimated_tokens = len(libraries) * LLM_MAX_TOKENS_PER_LIB + 500
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
        
        # Warning if truncated
        if finish_reason == "length":
            print(f"[llm_validator] Warning: Response truncated at {max_tokens} tokens")
        
        # Parse JSON from response
        return parse_llm_response(output_text)
        
    except Exception as e:
        print(f"[llm_validator] Error calling LLM API: {e}")
        return []


def parse_llm_response(output_text: str) -> List[Dict]:
    """Extract JSON array from LLM response."""
    # Try markdown code block first
    if "```json" in output_text:
        start = output_text.find("```json") + 7
        end = output_text.find("```", start)
        if end != -1:
            json_text = output_text[start:end].strip()
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
            print(f"[llm_validator] JSON parse error: {e}")
            return []
    
    print("[llm_validator] Could not find JSON array in response")
    return []


def classify_libraries(libraries: List[str]) -> List[Dict]:
    """
    Classify all libraries, batching if necessary.
    
    Args:
        libraries: List of unique library names
        
    Returns:
        List of all classification results
    """
    if not libraries:
        return []
    
    # Deduplicate and sort
    unique_libs = sorted(set(libraries))
    
    if len(unique_libs) <= LLM_BATCH_SIZE:
        return classify_batch(unique_libs)
    
    # Process in batches
    all_results = []
    total_batches = (len(unique_libs) + LLM_BATCH_SIZE - 1) // LLM_BATCH_SIZE
    
    for i in range(0, len(unique_libs), LLM_BATCH_SIZE):
        batch = unique_libs[i:i + LLM_BATCH_SIZE]
        batch_num = (i // LLM_BATCH_SIZE) + 1
        print(f"[llm_validator] Processing batch {batch_num}/{total_batches} ({len(batch)} libraries)")
        
        batch_results = classify_batch(batch)
        all_results.extend(batch_results)
    
    return all_results


def collect_unique_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict
) -> Set[str]:
    """
    Collect unique libraries from manifest dependencies and detected imports.
    
    Args:
        manifest_deps: Dependencies from manifests {"python": [...], "javascript": [...]}
        import_packages: Import packages {"python_imports": [...], "javascript_imports": [...]}
        
    Returns:
        Set of unique library/package names
    """
    unique = set()
    
    # Add manifest dependencies
    for lang, deps in manifest_deps.items():
        for dep in deps:
            unique.add(dep)
    
    # Add detected import packages
    for pkg in import_packages.get("python_imports", []):
        package_name = pkg.get("package", "")
        if package_name:
            unique.add(package_name)
    
    for pkg in import_packages.get("javascript_imports", []):
        package_name = pkg.get("package", "")
        if package_name:
            unique.add(package_name)
    
    return unique


def build_validation_result(
    classifications: List[Dict],
    import_packages: Dict
) -> Dict:
    """
    Build the final validation result with AI libraries and source mappings.
    
    Args:
        classifications: LLM classification results
        import_packages: Import packages with source files
        
    Returns:
        Structured validation result
    """
    # Separate AI-positive and non-AI
    ai_positive = []
    non_ai = []
    
    for item in classifications:
        lib_name = item.get("library", "")
        classification = item.get("classification", "")
        confidence = item.get("confidence", "LOW")
        reason = item.get("reason", "")
        
        if classification == "AI_POSITIVE" and confidence == "HIGH":
            ai_positive.append({
                "library": lib_name,
                "confidence": confidence,
                "reason": reason
            })
        else:
            non_ai.append({
                "library": lib_name,
                "classification": classification,
                "confidence": confidence,
                "reason": reason
            })
    
    # Build import lookup for source files
    import_lookup = {}
    for pkg in import_packages.get("python_imports", []):
        import_lookup[pkg.get("package", "")] = {
            "language": "python",
            "source_files": pkg.get("source_files", [])
        }
    for pkg in import_packages.get("javascript_imports", []):
        import_lookup[pkg.get("package", "")] = {
            "language": "javascript",
            "source_files": pkg.get("source_files", [])
        }
    
    # Enrich AI libraries with source files
    ai_libraries = []
    for lib in ai_positive:
        lib_name = lib["library"]
        entry = {
            "library": lib_name,
            "confidence": lib["confidence"],
            "reason": lib["reason"],
            "source_files": []
        }
        
        # Match with imports
        if lib_name in import_lookup:
            entry["source_files"] = import_lookup[lib_name]["source_files"]
            entry["language"] = import_lookup[lib_name]["language"]
        
        ai_libraries.append(entry)
    
    return {
        "ai_libraries": ai_libraries,
        "non_ai_libraries": [lib["library"] for lib in non_ai],
        "total_classified": len(classifications),
        "total_ai_positive": len(ai_libraries),
        "total_non_ai": len(non_ai),
        "model_used": LLM_MODEL
    }


def validate_libraries(
    manifest_deps: Dict[str, List[str]],
    import_packages: Dict,
    resolved_packages: Optional[Dict] = None
) -> Optional[Dict]:
    """
    Main validation function - collects libraries, classifies, returns result.
    
    Args:
        manifest_deps: Dependencies from manifests {"python": [...], "javascript": [...]}
        import_packages: Import packages from /filtered-imports endpoint
        resolved_packages: Optional resolved/merged packages from /resolve-packages
        
    Returns:
        Validation result or None if failed
    """
    # If resolved_packages is provided, use it (already deduplicated)
    if resolved_packages and resolved_packages.get("unified_packages"):
        return validate_from_resolved(resolved_packages, import_packages)
    
    # Step 1: Collect unique libraries (no duplicates)
    unique_libraries = collect_unique_libraries(manifest_deps, import_packages)
    
    if not unique_libraries:
        return {
            "ai_libraries": [],
            "non_ai_libraries": [],
            "total_classified": 0,
            "total_ai_positive": 0,
            "total_non_ai": 0,
            "model_used": LLM_MODEL
        }
    
    print(f"[llm_validator] Classifying {len(unique_libraries)} unique libraries...")
    
    # Step 2: Classify with LLM
    classifications = classify_libraries(list(unique_libraries))
    
    if not classifications:
        return None
    
    # Step 3: Build result with source file mappings
    result = build_validation_result(classifications, import_packages)
    
    return result


def validate_from_resolved(
    resolved_packages: Dict,
    import_packages: Dict
) -> Optional[Dict]:
    """
    Validate using pre-resolved packages (already deduplicated).
    
    Args:
        resolved_packages: Output from /resolve-packages endpoint
        import_packages: Import packages for source file lookup
        
    Returns:
        Validation result or None if failed
    """
    unified = resolved_packages.get("unified_packages", [])
    
    if not unified:
        return {
            "ai_libraries": [],
            "non_ai_libraries": [],
            "total_classified": 0,
            "total_ai_positive": 0,
            "total_non_ai": 0,
            "model_used": LLM_MODEL
        }
    
    # Extract library names only
    library_names = [pkg.get("library", "") for pkg in unified if pkg.get("library")]
    
    print(f"[llm_validator] Classifying {len(library_names)} resolved libraries...")
    
    # Classify with LLM
    classifications = classify_libraries(library_names)
    
    if not classifications:
        return None
    
    # Build lookup from unified packages (already has source files)
    pkg_lookup = {}
    for pkg in unified:
        lib_name = pkg.get("library", "")
        if lib_name:
            pkg_lookup[lib_name] = {
                "language": pkg.get("language"),
                "source_files": pkg.get("source_files", []),
                "source": pkg.get("source", "import"),
                "resolved_imports": pkg.get("resolved_imports", [])
            }
    
    # Separate AI-positive and non-AI
    ai_libraries = []
    non_ai = []
    
    for item in classifications:
        lib_name = item.get("library", "")
        classification = item.get("classification", "")
        confidence = item.get("confidence", "LOW")
        reason = item.get("reason", "")
        
        if classification == "AI_POSITIVE" and confidence == "HIGH":
            entry = {
                "library": lib_name,
                "confidence": confidence,
                "reason": reason,
                "source_files": []
            }
            
            # Enrich from lookup
            if lib_name in pkg_lookup:
                entry["source_files"] = pkg_lookup[lib_name]["source_files"]
                entry["language"] = pkg_lookup[lib_name]["language"]
            
            ai_libraries.append(entry)
        else:
            non_ai.append(lib_name)
    
    return {
        "ai_libraries": ai_libraries,
        "non_ai_libraries": non_ai,
        "total_classified": len(classifications),
        "total_ai_positive": len(ai_libraries),
        "total_non_ai": len(non_ai),
        "model_used": LLM_MODEL
    }

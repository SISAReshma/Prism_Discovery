# AI Model Deprecation Cache

This directory contains deprecation data for AI models from multiple providers.

## Files

### `anthropic_deprecations.json`
- **Provider**: Anthropic (Claude)
- **Models**: 22 tracked (15 deprecated/retired, 7 active)
- **Terminology**: Uses "retirement" for end-of-life
- **Key Fields**: `retirement_date`, `tier` (opus/sonnet/haiku)
- **Source**: Anthropic API documentation and announcements

### `openai_deprecations.json`
- **Provider**: OpenAI (GPT)
- **Models**: TBD (currently empty)
- **Terminology**: Uses "shutdown" for end-of-life
- **Key Fields**: `shutdown_date`, `legacy_endpoints[]`
- **Source**: OpenAI deprecation notices

### `google_deprecations.json`
- **Provider**: Google (Gemini/Imagen/Veo)
- **Models**: 32 tracked (31 deprecated/shutdown, 1 active)
- **Terminology**: Uses "shutdown" for end-of-life
- **Key Fields**: `shutdown_date`, `tier` (pro/flash/ultra/video), `multimodal_capabilities[]`
- **Model Families**:
  - **Gemini 3**: Latest models (preview state)
  - **Gemini 2.5**: Deprecated → Gemini 3
  - **Gemini 2.0**: Deprecated → Gemini 2.5 → Gemini 3
  - **Imagen**: Image generation models
  - **Veo**: Video generation models
  - **Embeddings**: Text embedding models
- **Source**: https://ai.google.dev/gemini-api/docs/deprecations

## Schema Structure

Each JSON file follows this structure:

```json
{
  "provider": "ProviderName",
  "source_url": "https://...",
  "last_updated": "YYYY-MM-DD",
  "schema_version": "1.0",
  "lifecycle_definitions": { ... },
  "deprecation_policy": { ... },
  "model_status": [
    {
      "model_id": "...",
      "lifecycle_state": "deprecated|retired|shutdown|active",
      "recommended_replacement": "...",
      "shutdown_date": "YYYY-MM-DD"
    }
  ],
  "retired_models": [ ... ]
}
```

## Lifecycle States

- **active**: Fully supported model
- **preview**: Experimental/preview model
- **deprecated**: Has announced end-of-life date
- **retired/shutdown**: No longer available

## Replacement Chain Building

The `model_deprecation_checker.py` module reads these files and builds replacement chains:

```
gemini-2.0-flash → gemini-2.5-flash → gemini-3-flash-preview (active)
```

This ensures we always find the final active replacement for any deprecated model.

## Update Schedule

These files should be updated:
- When providers announce new deprecations
- When shutdown dates change
- When new replacement models are released
- Recommended: Daily automated check

## Integration

Used by:
- `model_deprecation_checker.py` - Loads and processes deprecation data
- `aibom_generator.py` - Creates CycloneDX vulnerabilities for deprecated models
- Database schema: `db_schemas/deprecated_models_schema.json`

## Testing

Run tests with:
```python
from model_deprecation_checker import get_deprecation_checker

checker = get_deprecation_checker()
result = checker.check_model("gemini-2.5-pro")
print(result)
```

Expected output:
```python
{
  'model_id': 'gemini-2.5-pro',
  'lifecycle_state': 'deprecated',
  'severity': 'HIGH',
  'replacement_chain': ['gemini-2.5-pro', 'gemini-3-pro-preview'],
  'recommended_replacement': 'gemini-3-pro-preview',
  ...
}
```

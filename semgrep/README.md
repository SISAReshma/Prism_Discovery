# AIBOM Semgrep Rules

Organized semgrep rules for import detection across supported languages.

## Structure

```
semgrep/
├── README.md                    # This file
├── python/
│   └── python_imports.yml       # Python import detection rules
└── javascript/
    └── javascript_imports.yml   # JavaScript/TypeScript import detection rules
```

## Usage

These rules are automatically used by the `/semgrep-imports-scan` endpoint to detect:

### Python
- `from module import item` (from-import)
- `import module` (direct-import)
- `from . import item` (relative-import)

### JavaScript/TypeScript
- `import { X } from 'module'` (named-import)
- `import X from 'module'` (default-import)
- `import * as X from 'module'` (namespace-import)
- `require('module')` (require)
- `import('module')` (dynamic-import)

## Adding New Rules

1. Create a new `.yml` file in the appropriate language folder
2. Follow the Semgrep rule format
3. Use `metadata.import_type` to categorize the import type

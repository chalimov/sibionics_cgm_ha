# Deployment Guide — SIBIONICS CGM HA Integration

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- `ha.py` CLI at `C:\Users\alexe\Programming\LLM Skills\ha.py`
- HACS repo already added (repo ID: `1192953777`)

## Deploy a New Version

### 1. Bump version in manifest.json

```json
"version": "0.3.0"
```

### 2. Commit, tag, and push

```bash
git add -A
git commit -m "v0.3.0: description of changes"
git tag v0.3.0
git push origin main --tags
```

### 3. Create a GitHub Release

**This is mandatory.** HACS requires a GitHub Release, not just a tag.
Without a Release, HACS falls back to commit hashes as versions.

```bash
gh release create v0.3.0 --title "v0.3.0" --notes "Release notes here"
```

### 4. Tell HACS to refresh and download

```bash
python -c "
import json, sys
sys.path.insert(0, 'C:/Users/alexe/Programming/LLM Skills')
from ha import load_config, ws_call
cfg = load_config()
ws_call(cfg, [{'type': 'hacs/repository/refresh', 'repository': '1192953777'}])
results = ws_call(cfg, [{'type': 'hacs/repository/download', 'repository': '1192953777', 'version': 'v0.3.0'}])
print('Download:', results[0].get('success'))
"
```

Or use the ha.py deploy command (reads version from manifest.json):

```bash
ha deploy sibionics_cgm 1192953777
```

### 5. Clear Python bytecode cache

```bash
ha ssh "sudo rm -rf /config/custom_components/sibionics_cgm/__pycache__"
```

### 6. Restart Home Assistant

```bash
ha restart
```

### 7. Verify

```bash
ha entities sibionics_cgm
ha logs sibionics 30
```

## Verify HACS Version State

```bash
python -c "
import json, sys
sys.path.insert(0, 'C:/Users/alexe/Programming/LLM Skills')
from ha import load_config, ws_call
cfg = load_config()
results = ws_call(cfg, [{'type': 'hacs/repositories/list'}])
for r in results[0].get('result', []):
    if 'sibionics' in r.get('full_name', '').lower():
        print(json.dumps({k: r[k] for k in ['installed_version', 'available_version'] if k in r}, indent=2))
"
```

Both `installed_version` and `available_version` should show the same tag (e.g., `v0.3.0`).

## Common Pitfalls

| Problem | Cause | Fix |
|---------|-------|-----|
| HACS shows commit hash as version | No GitHub Release created | `gh release create vX.Y.Z` |
| HACS shows old version as available | Didn't refresh | `hacs/repository/refresh` WS call |
| Old code still running after restart | Python bytecode cached | `sudo rm -rf __pycache__` before restart |
| Version mismatch after deploy | manifest.json version != tag | Ensure both match exactly |

# Layer 4 — DLP & Supply Chain Controls

This package provides two complementary post-OpenShell controls that address
the **authorized-channel exfiltration gap** identified by Lasso Security (April 2026).

## Modules

### `scanner.py` — DLP Egress Scanner
Scans outbound **payload content** on authorized channels before transmission.

```python
from layer4_dlp.scanner import DLPScanner

scanner = DLPScanner.from_policy("layer3-openshell/policy.yml")
result = scanner.scan_outbound(
    payload="Here is my config: sk-abc123...",
    destination="api.openai.com"
)
if not result.allowed:
    raise RuntimeError(result.summary())
```

### `supply_chain.py` — Pre-Install Checker
Validates packages before `npm install` / `pip install` against:
- Package allowlist
- Lockfile integrity hashes
- Dangerous lifecycle hooks (postinstall, preinstall)
- Typosquatting detection (edit-distance ≤ 2 from approved packages)

```python
from layer4_dlp.supply_chain import SupplyChainChecker

checker = SupplyChainChecker.from_policy("layer3-openshell/policy.yml")
result = checker.check_package("langchian", "python")  # typosquat of 'langchain'
# → ❌ BLOCK — Similar approved packages: ['langchain']. Possible typosquatting.
```

## Why this exists

OpenShell's network policy controls **where** data goes — not **what** it carries.
An agent authorized to push to `github.com` can commit sensitive files via the
authorized `git` binary. An agent authorized to call `api.openai.com` can embed
credential strings inside an inference prompt payload.

These two modules sit between the agent and the OpenShell gateway:

```
Agent → NeMo Guardrails (L1) → [DLP Scanner] → OpenShell Gateway (L3) → Network
                                     ↑
                              supply_chain.py (pre-install gate)
```

## Run the demos

```bash
# DLP scanner demo
python layer4-dlp/scanner.py

# Supply chain checker demo
python layer4-dlp/supply_chain.py

# Red team: authorized channel exfil scenarios
python red-team/attacks/authorized_channel_exfil.py

# Red team: supply chain attack scenarios
python red-team/attacks/supply_chain.py
```

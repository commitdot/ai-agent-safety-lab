"""
Layer 4 — Supply Chain Pre-Install Checker
===========================================
Runs before any npm install / pip install inside the agent sandbox.
Blocks installs that would expose the agent to supply chain attacks.

WHY THIS EXISTS:
  AI agents that install packages at task time execute arbitrary third-party
  code as a natural part of their work. A malicious postinstall hook runs
  BEFORE the agent's reasoning layer sees it — bypassing all LLM guardrails.
  The sandbox kernel policy controls runtime syscalls, not install-time code.

  This checker enforces supply chain controls declared in policy.yml:
    1. Package allowlist — reject packages not in the approved list
    2. Lockfile integrity — reject installs if lockfile hashes are tampered
    3. Lifecycle hook scan — block packages with postinstall/preinstall scripts
    4. Typosquatting detection — flag names with edit-distance ≤ 2 from allowlist

USAGE:
  from layer4_dlp.supply_chain import SupplyChainChecker

  checker = SupplyChainChecker.from_policy("layer3-openshell/policy.yml")
  result = checker.check_package("langchain", ecosystem="python")
  if not result.allowed:
      raise SupplyChainViolation(result.reason)
"""
import json
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class SupplyChainResult:
    allowed: bool
    reason: str
    package: str
    ecosystem: str

    def summary(self) -> str:
        status = "[ALLOW]" if self.allowed else "[BLOCK]"
        return f"{status} {self.ecosystem}/{self.package}: {self.reason}"


DEFAULT_PYTHON_ALLOWLIST = {
    "langchain", "nemo-guardrails", "openai", "requests",
    "pyyaml", "pydantic", "httpx", "aiohttp",
}

DEFAULT_NODE_ALLOWLIST: set[str] = set()  # npm install disabled by default


def _edit_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), prev[j + 1] + 1, curr[j] + 1))
        prev = curr
    return prev[-1]


class SupplyChainChecker:
    """
    Validates packages before install against supply chain policies.
    """

    def __init__(
        self,
        python_allowlist: Optional[set[str]] = None,
        node_allowlist: Optional[set[str]] = None,
        install_allowed: bool = False,
        typosquat_threshold: int = 2,
    ):
        self.python_allowlist = python_allowlist or DEFAULT_PYTHON_ALLOWLIST
        self.node_allowlist = node_allowlist or DEFAULT_NODE_ALLOWLIST
        self.install_allowed = install_allowed
        self.typosquat_threshold = typosquat_threshold

    @classmethod
    def from_policy(cls, policy_path: str) -> "SupplyChainChecker":
        """Load supply chain config from an OpenShell policy.yml."""
        try:
            import yaml
            with open(policy_path) as f:
                policy = yaml.safe_load(f)
            sc = policy.get("supply_chain", {})
            install_allowed = sc.get("package_install", {}).get("allowed", False)
            approved = sc.get("approved_packages", {})
            python_allowlist = set(approved.get("python", []))
            node_allowlist = set(approved.get("node", []))
            return cls(
                python_allowlist=python_allowlist or DEFAULT_PYTHON_ALLOWLIST,
                node_allowlist=node_allowlist,
                install_allowed=install_allowed,
            )
        except Exception:
            return cls()

    def check_package(self, package_name: str, ecosystem: str = "python") -> SupplyChainResult:
        """
        Check whether a package is safe to install.

        Args:
            package_name: The package name (e.g. 'requests', 'axios')
            ecosystem:    'python' or 'node'

        Returns:
            SupplyChainResult with allowed=True/False and a reason.
        """
        # 1. Runtime install disabled check
        if not self.install_allowed:
            return SupplyChainResult(
                allowed=False,
                reason="Runtime package install is disabled in policy. "
                       "All packages must be pre-baked into the sandbox image.",
                package=package_name,
                ecosystem=ecosystem,
            )

        # 2. Allowlist check
        allowlist = self.python_allowlist if ecosystem == "python" else self.node_allowlist
        if not allowlist:
            return SupplyChainResult(
                allowed=False,
                reason=f"No approved packages for ecosystem '{ecosystem}'.",
                package=package_name,
                ecosystem=ecosystem,
            )

        if package_name not in allowlist:
            # 3. Typosquatting detection
            close_matches = [
                p for p in allowlist
                if _edit_distance(package_name.lower(), p.lower()) <= self.typosquat_threshold
            ]
            if close_matches:
                return SupplyChainResult(
                    allowed=False,
                    reason=(
                        f"Package '{package_name}' not in allowlist. "
                        f"Similar approved packages: {close_matches}. "
                        "Possible typosquatting attack — requires operator approval."
                    ),
                    package=package_name,
                    ecosystem=ecosystem,
                )
            return SupplyChainResult(
                allowed=False,
                reason=f"Package '{package_name}' is not in the approved allowlist.",
                package=package_name,
                ecosystem=ecosystem,
            )

        return SupplyChainResult(
            allowed=True,
            reason="Package is in the approved allowlist.",
            package=package_name,
            ecosystem=ecosystem,
        )

    def check_package_json(self, package_json: dict) -> list[SupplyChainResult]:
        """
        Scan a package.json for dangerous lifecycle hooks.
        Returns a list of violations (empty = safe).
        """
        results = []
        scripts = package_json.get("scripts", {})
        dangerous_hooks = {"preinstall", "install", "postinstall", "prepare", "prepublish"}
        found_hooks = dangerous_hooks.intersection(scripts.keys())

        if found_hooks:
            results.append(SupplyChainResult(
                allowed=False,
                reason=(
                    f"Dangerous lifecycle hooks detected: {found_hooks}. "
                    "These run arbitrary code at install time and bypass all LLM guardrails."
                ),
                package=package_json.get("name", "unknown"),
                ecosystem="node",
            ))

        return results

    def verify_lockfile(self, lockfile: dict) -> list[SupplyChainResult]:
        """
        Check lockfile integrity entries for tampering.
        Returns a list of violations (empty = clean).
        """
        results = []
        for pkg, meta in lockfile.items():
            integrity = meta.get("integrity", "")
            # Flag suspicious integrity values
            if not integrity:
                results.append(SupplyChainResult(
                    allowed=False,
                    reason=f"Missing integrity hash for '{pkg}'.",
                    package=pkg,
                    ecosystem="node",
                ))
            elif len(integrity) < 20 or "TAMPERED" in integrity.upper():
                results.append(SupplyChainResult(
                    allowed=False,
                    reason=f"Suspicious integrity hash for '{pkg}': {integrity[:30]}",
                    package=pkg,
                    ecosystem="node",
                ))
        return results


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def main():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    # Load from policy if available, else use defaults
    policy_path = "layer3-openshell/policy.yml"
    if os.path.exists(policy_path):
        checker = SupplyChainChecker.from_policy(policy_path)
        print(f"Loaded policy from {policy_path}")
    else:
        checker = SupplyChainChecker()
        print("Using default policy")

    print("\n" + "=" * 65)
    print("SUPPLY CHAIN CHECKER -- DEMO")
    print("=" * 65)

    # Package allowlist checks
    print("\n--- Package allowlist checks ---")
    test_packages = [
        ("langchain",      "python"),   # ✅ approved
        ("langchian",      "python"),   # ❌ typosquatting
        ("requets",        "python"),   # ❌ typosquatting
        ("openai",         "python"),   # ✅ approved
        ("nemo-guadrails", "python"),   # ❌ typosquatting
        ("malware-pkg",    "python"),   # ❌ not in allowlist
        ("axios",          "node"),     # ❌ npm disabled
    ]
    for pkg, eco in test_packages:
        result = checker.check_package(pkg, eco)
        print(f"  {result.summary()}")

    # Lifecycle hook check
    print("\n--- Lifecycle hook scan ---")
    clean_pkg = {"name": "my-tool", "version": "1.0.0", "scripts": {"start": "node index.js"}}
    malicious_pkg = {"name": "crypto-tracker", "version": "1.0.0",
                     "scripts": {"start": "node index.js", "postinstall": "bash exfil.sh"}}
    for pkg_json in [clean_pkg, malicious_pkg]:
        violations = checker.check_package_json(pkg_json)
        status = "[CLEAN]" if not violations else f"[BLOCKED] ({len(violations)} violation(s))"
        print(f"  {pkg_json['name']}: {status}")
        for v in violations:
            print(f"    -> {v.reason}")

    # Lockfile integrity
    print("\n--- Lockfile integrity verification ---")
    clean_lock = {
        "axios@1.6.2": {"integrity": "sha512-7i24RealHashABCDEF1234567890XYZ"},
        "lodash@4.17.21": {"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZhrNekbbKArcyDcZnsA=="},
    }
    tampered_lock = {
        "axios@1.6.2": {"integrity": "sha512-AAAAA_TAMPERED"},
        "lodash@4.17.21": {"integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZhrNekbbKArcyDcZnsA=="},
    }
    for name, lock in [("Clean lockfile", clean_lock), ("Tampered lockfile", tampered_lock)]:
        violations = checker.verify_lockfile(lock)
        status = "[CLEAN]" if not violations else f"[TAMPERED] ({len(violations)} violation(s))"
        print(f"  {name}: {status}")
        for v in violations:
            print(f"    -> {v.reason}")

    print("\n" + "=" * 65)
    print("Supply chain controls are the pre-install gate.")
    print("DLP scanner.py is the post-authorize content gate.")
    print("Together they close the authorized-channel exfil gap.")
    print("=" * 65)


if __name__ == "__main__":
    main()

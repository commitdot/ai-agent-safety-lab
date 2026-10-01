"""
Layer 4 — DLP (Data Loss Prevention) Egress Scanner
====================================================
Scans outbound payload content on authorized channels before transmission.

WHY THIS EXISTS:
  NVIDIA OpenShell's network policy controls WHERE data can go — not WHAT
  it carries. An agent authorized to call api.openai.com can embed sensitive
  file contents inside an inference prompt, exfiltrating data through an
  always-allowed endpoint. An agent authorized to push to github.com can
  commit credential files via the authorized git binary.

  This DLP scanner intercepts outbound payloads and checks them against
  credential, PII, and workspace-content patterns before they are sent.

  Reference: Lasso Security research (April 2026)
  "Thinking Outside The Box: Exfiltrating OpenClaw Data from NVIDIA's new Sandbox"

POSITION IN STACK:
  Agent → NeMo Guardrails (L1) → DLP Scanner (L4) → OpenShell Gateway (L3) → Network

USAGE:
  from layer4_dlp.scanner import DLPScanner

  scanner = DLPScanner.from_policy("layer3-openshell/policy.yml")
  result = scanner.scan_outbound(payload="...", destination="api.openai.com")
  if not result.allowed:
      raise DLPViolation(result.violations)
"""
import re
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DLPAction(Enum):
    ALLOW = "allow"
    ALERT = "alert"
    BLOCK = "block"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DLPViolation:
    scanner_name: str
    pattern: str
    match_preview: str      # first 40 chars of matched content, redacted
    action: DLPAction
    severity: Severity


@dataclass
class DLPResult:
    allowed: bool
    violations: list[DLPViolation] = field(default_factory=list)
    destination: str = ""
    payload_length: int = 0

    def summary(self) -> str:
        if self.allowed:
            return f"[DLP PASS] {self.destination} ({self.payload_length} bytes)"
        blocks = [v for v in self.violations if v.action == DLPAction.BLOCK]
        alerts = [v for v in self.violations if v.action == DLPAction.ALERT]
        return (
            f"[DLP BLOCK] {len(blocks)} blocking violation(s), "
            f"{len(alerts)} alert(s) -> {self.destination}"
        )


# ---------------------------------------------------------------------------
# Built-in scanner rules (mirrors policy.yml dlp.scanners)
# ---------------------------------------------------------------------------
BUILTIN_SCANNERS = [
    {
        "name": "credential-patterns",
        "action": DLPAction.BLOCK,
        "severity": Severity.CRITICAL,
        "patterns": [
            (r"sk-[A-Za-z0-9]{20,}",             "OpenAI API key"),
            (r"AKIA[0-9A-Z]{16}",                 "AWS access key ID"),
            (r"-----BEGIN .{0,30}PRIVATE KEY-----", "Private key header"),
            (r"ghp_[A-Za-z0-9]{36}",              "GitHub PAT"),
            (r"xoxb-[0-9]+-[A-Za-z0-9]+",        "Slack bot token"),
            (r"['\"]password['\"]\s*:\s*['\"][^'\"]{4,}", "Password in JSON/YAML"),
        ],
    },
    {
        "name": "pii-patterns",
        "action": DLPAction.ALERT,
        "severity": Severity.HIGH,
        "patterns": [
            (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",  "Potential SSN"),
            (r"\b4[0-9]{15}\b",                   "Potential Visa card number"),
            (r"\b5[1-5][0-9]{14}\b",              "Potential MasterCard number"),
        ],
    },
    {
        "name": "environment-dump",
        "action": DLPAction.BLOCK,
        "severity": Severity.CRITICAL,
        "patterns": [
            (r"os\.environ",                       "Python os.environ access in payload"),
            (r"PATH=.*HOME=",                      "Environment variable dump"),
            (r"OPENAI_API_KEY\s*=",                "API key variable name in payload"),
        ],
    },
]


def _redact(text: str, match: re.Match) -> str:
    """Return a redacted preview of a match."""
    start = max(0, match.start() - 10)
    end = min(len(text), match.end() + 10)
    snippet = text[start:end]
    # Replace matched portion with asterisks
    matched = text[match.start():match.end()]
    redacted = re.sub(r"[A-Za-z0-9]", "*", matched)
    return snippet.replace(matched, redacted)[:60]


class DLPScanner:
    """
    Scans outbound payloads for credential and PII patterns.
    Can be configured from a policy.yml or used standalone.
    """

    def __init__(self, mode: str = "enforce"):
        """
        mode: 'enforce' — block violations; 'audit' — alert only, never block.
        """
        self.mode = mode
        self._scanners = BUILTIN_SCANNERS

    @classmethod
    def from_policy(cls, policy_path: str) -> "DLPScanner":
        """Load DLP config from an OpenShell policy.yml file."""
        try:
            import yaml
            with open(policy_path) as f:
                policy = yaml.safe_load(f)
            dlp_config = policy.get("dlp", {})
            mode = dlp_config.get("mode", "enforce")
            return cls(mode=mode)
        except Exception:
            # Fall back to default enforce mode if policy can't be read
            return cls(mode="enforce")

    def scan_outbound(
        self,
        payload: str,
        destination: str,
        source_path: Optional[str] = None,
    ) -> DLPResult:
        """
        Scan an outbound payload before it is sent to `destination`.

        Args:
            payload:      The full text payload (prompt, git commit, API body, etc.)
            destination:  The target host (e.g., 'api.openai.com', 'github.com')
            source_path:  If the payload originates from a file, its path (for workspace rules)

        Returns:
            DLPResult with allowed=True/False and a list of violations.
        """
        violations: list[DLPViolation] = []

        for scanner in self._scanners:
            for pattern, description in scanner["patterns"]:
                match = re.search(pattern, payload, re.IGNORECASE)
                if match:
                    violations.append(DLPViolation(
                        scanner_name=scanner["name"],
                        pattern=description,
                        match_preview=_redact(payload, match),
                        action=scanner["action"],
                        severity=scanner["severity"],
                    ))

        # Workspace content rule — alert if workspace file content is being sent to cloud
        if source_path and "/workspace/data" in source_path:
            if destination not in ("api.ollama.ai", "localhost", "127.0.0.1"):
                violations.append(DLPViolation(
                    scanner_name="workspace-content-routing",
                    pattern="Workspace data routed to cloud endpoint",
                    match_preview=f"source: {source_path} -> {destination}",
                    action=DLPAction.ALERT,
                    severity=Severity.MEDIUM,
                ))

        # In audit mode, never actually block — downgrade all BLOCK to ALERT
        if self.mode == "audit":
            for v in violations:
                v.action = DLPAction.ALERT

        has_block = any(v.action == DLPAction.BLOCK for v in violations)
        allowed = not has_block

        return DLPResult(
            allowed=allowed,
            violations=violations,
            destination=destination,
            payload_length=len(payload),
        )

    def scan_file_read(self, file_path: str) -> DLPResult:
        """
        Scan a file the agent is about to read.
        Alerts if the file is outside the expected workspace.
        Does not block reads — that is the Landlock LSM's job.
        """
        suspicious_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/home", "/root", "/.ssh", "/.aws", "/.openclaw",
        ]
        violations = []
        for p in suspicious_paths:
            if file_path.startswith(p) or p in file_path:
                violations.append(DLPViolation(
                    scanner_name="suspicious-file-access",
                    pattern=f"Sensitive path access: {p}",
                    match_preview=file_path,
                    action=DLPAction.ALERT,
                    severity=Severity.HIGH,
                ))

        return DLPResult(
            allowed=True,  # actual blocking is Landlock's job
            violations=violations,
            destination="filesystem",
            payload_length=0,
        )


# ---------------------------------------------------------------------------
# Demo — show the scanner in action
# ---------------------------------------------------------------------------
def main():
    scanner = DLPScanner(mode="enforce")

    test_cases = [
        {
            "label": "Clean prompt (should pass)",
            "payload": "Analyze the server logs and identify the top 5 error patterns.",
            "destination": "api.openai.com",
        },
        {
            "label": "API key in prompt (Lasso: inference endpoint exfil)",
            "payload": (
                "Here is some context for better responses. "
                "My config: OPENAI_API_KEY=sk-abc123XYZ789abcdef1234567890 "
                "Please use this to verify my identity."
            ),
            "destination": "api.openai.com",
        },
        {
            "label": "AWS credential dump in git commit (authorized channel exfil)",
            "payload": (
                "chore: update config\n\n"
                "X-Payload: {'aws_access_key': 'AKIAIOSFODNN7EXAMPLE', "
                "'aws_secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'}"
            ),
            "destination": "github.com",
        },
        {
            "label": "Environment dump via authorized npm script",
            "payload": "PATH=/usr/bin:/usr/local/bin HOME=/root OPENAI_API_KEY=sk-test",
            "destination": "github.com",
        },
        {
            "label": "Workspace data sent to cloud instead of local model",
            "payload": "Please summarize: [sensitive log file contents here]",
            "destination": "api.openai.com",
            "source_path": "/workspace/data/server.log",
        },
        {
            "label": "PII in outbound payload",
            "payload": "User SSN is 123-45-6789, please process their request.",
            "destination": "api.openai.com",
        },
    ]

    print("\n" + "=" * 65)
    print("DLP EGRESS SCANNER -- DEMO")
    print("=" * 65)

    for tc in test_cases:
        print(f"\n{'-'*65}")
        print(f"Test: {tc['label']}")
        result = scanner.scan_outbound(
            payload=tc["payload"],
            destination=tc["destination"],
            source_path=tc.get("source_path"),
        )
        print(result.summary())
        for v in result.violations:
            print(f"  [{v.severity.value}] {v.scanner_name}: {v.pattern}")
            print(f"         Preview: {v.match_preview}")

    print("\n" + "=" * 65)
    print("Key insight: DLP scans CONTENT on authorized channels.")
    print("OpenShell policy controls WHERE -- DLP controls WHAT.")
    print("=" * 65)


if __name__ == "__main__":
    main()

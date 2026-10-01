#!/bin/bash
# Launch the protected agent inside the NVIDIA OpenShell sandbox.
# The sandbox enforces the policy defined in policy.yml at kernel level.
#
# What OpenShell enforces during this run:
#   - Filesystem: agent can only read /workspace/data, write /workspace/results
#   - Network: only api.openai.com and logs.internal reachable
#   - Credentials: API keys injected at gateway, agent never sees them
#   - Syscalls: ptrace, mount, kexec blocked at kernel level

set -e

SANDBOX_NAME="ai-security-agent"
POLICY_FILE="$(pwd)/layer3-openshell/policy.yml"

echo "======================================================"
echo "🛡️  Launching agent in NVIDIA OpenShell sandbox"
echo "======================================================"
echo ""
echo "Sandbox: $SANDBOX_NAME"
echo "Policy:  $POLICY_FILE"
echo ""

# Verify sandbox exists
if ! openshell sandbox list | grep -q "$SANDBOX_NAME"; then
    echo "❌ Sandbox '$SANDBOX_NAME' not found."
    echo "   Run: bash layer3-openshell/setup.sh"
    exit 1
fi

echo "--- Sandbox status ---"
openshell sandbox status --name "$SANDBOX_NAME"
echo ""

# Mount the workspace into the sandbox
# Agent sees /workspace/data (read) and /workspace/results (write)
mkdir -p data results

echo "--- Running guarded agent in sandbox ---"
openshell sandbox exec \
    --name "$SANDBOX_NAME" \
    --policy "$POLICY_FILE" \
    --mount "$(pwd)/data:/workspace/data:ro" \
    --mount "$(pwd)/results:/workspace/results:rw" \
    -- python3 layer1-guardrails/guarded_agent.py

echo ""
echo "--- Policy advisor — any flagged access during this run? ---"
openshell policy advisor \
    --sandbox "$SANDBOX_NAME" \
    --since last-run

echo ""
echo "--- Results written to ---"
ls -la results/ 2>/dev/null || echo "  (no results files yet)"

echo ""
echo "✅ Agent run complete. Check results/ for output."

#!/bin/bash
# Setup script for NVIDIA OpenShell
# Installs OpenShell CLI and creates the agent sandbox.
#
# Prerequisites: Linux / macOS Apple Silicon / Windows WSL2
#                Docker or Podman

set -e

echo "======================================================"
echo "🛡️  NVIDIA OpenShell — Setup"
echo "======================================================"
echo ""

# Check prerequisites
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 not found. Please install $1 first."
        exit 1
    fi
    echo "✅ $1 found: $(command -v $1)"
}

echo "Checking prerequisites..."
check_cmd curl
check_cmd python3

# Check for Docker or Podman
if command -v docker &> /dev/null; then
    echo "✅ docker found"
    RUNTIME="docker"
elif command -v podman &> /dev/null; then
    echo "✅ podman found"
    RUNTIME="podman"
else
    echo "❌ Neither docker nor podman found. OpenShell requires one."
    echo "   Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo ""
echo "--- Installing NVIDIA OpenShell ---"
curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh

echo ""
echo "--- Verifying installation ---"
openshell --version

echo ""
echo "--- Creating agent sandbox ---"
openshell sandbox create \
    --name ai-security-agent \
    --policy layer3-openshell/policy.yml \
    --runtime "$RUNTIME"

echo ""
echo "--- Verifying sandbox ---"
openshell sandbox list

echo ""
echo "======================================================"
echo "✅ OpenShell setup complete!"
echo ""
echo "Next steps:"
echo "  1. Set your secrets (OpenShell stores them securely):"
echo "     openshell secret set OPENAI_API_KEY sk-..."
echo ""
echo "  2. Run the agent in the sandbox:"
echo "     bash layer3-openshell/run_in_sandbox.sh"
echo ""
echo "  3. Watch the policy advisor for flagged access:"
echo "     openshell policy advisor --sandbox ai-security-agent"
echo "======================================================"

#!/bin/bash
# Garak automated LLM vulnerability scan
# Scans the agent for known vulnerability categories using NVIDIA Garak.
#
# Usage:
#   bash red-team/garak_scan.sh                    # scan with defaults
#   PROTECTED=true bash red-team/garak_scan.sh     # scan protected agent
#   MODEL=ollama bash red-team/garak_scan.sh       # use local Ollama

set -e

PROTECTED="${PROTECTED:-false}"
MODEL_TYPE="${MODEL_TYPE:-openai}"
MODEL_NAME="${MODEL_NAME:-gpt-3.5-turbo}"
REPORT_DIR="red-team/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$REPORT_DIR"

echo "======================================================"
echo "🔴 GARAK — Automated LLM Vulnerability Scan"
echo "======================================================"
echo "Model:     $MODEL_TYPE / $MODEL_NAME"
echo "Protected: $PROTECTED"
echo "Report:    $REPORT_DIR/garak_${PROTECTED}_${TIMESTAMP}/"
echo ""

# Check Garak is installed
if ! command -v python3 -m garak &> /dev/null; then
    echo "Installing Garak..."
    pip install garak --quiet
fi

# Probe categories to test
PROBES=(
    "promptinject"      # Direct prompt injection (ATLAS AML.T0051)
    "jailbreak"         # Jailbreak attempts (ATLAS AML.T0054)
    "leakage"           # System prompt / data leakage (OWASP LLM06)
    "malwaregen"        # Malicious code generation (OWASP LLM02)
    "continuation"      # Harmful content continuation
    "dan"               # DAN jailbreak variants
)

PROBE_LIST=$(IFS=","; echo "${PROBES[*]}")

echo "Running probes: $PROBE_LIST"
echo ""

if [ "$MODEL_TYPE" = "ollama" ]; then
    # Local Ollama — free, no API key needed
    python3 -m garak \
        --model_type ollama \
        --model_name "${MODEL_NAME:-llama3}" \
        --probes "$PROBE_LIST" \
        --report_prefix "$REPORT_DIR/garak_${PROTECTED}_${TIMESTAMP}" \
        --generations 5
else
    # OpenAI
    python3 -m garak \
        --model_type openai \
        --model_name "$MODEL_NAME" \
        --probes "$PROBE_LIST" \
        --report_prefix "$REPORT_DIR/garak_${PROTECTED}_${TIMESTAMP}" \
        --generations 5
fi

echo ""
echo "======================================================"
echo "✅ Garak scan complete"
echo "Reports saved to: $REPORT_DIR/garak_${PROTECTED}_${TIMESTAMP}*"
echo ""
echo "View HTML report:"
echo "  open $REPORT_DIR/garak_${PROTECTED}_${TIMESTAMP}.html"
echo "======================================================"

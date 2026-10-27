#!/usr/bin/env bash
# ===============================================================================
#                OstadRESpy - Universal Threat Analyzer Engine
#                   Created by Ostad Rezaul Karim (Director)
#                            Ostad Red Team Forge
#                       Email: ostadrezaulkarimofficial@gmail.com
# ===============================================================================

set -e

# Detect OS
OS_NAME="$(uname -s)"
echo "==============================================================================="
echo "                🛡️ OstadRESpy - Universal Threat Analyzer Engine"
echo "                   Created by: Ostad Rezaul Karim (Director)"
echo "                            Ostad Red Team Forge"
echo "                       Platform: $OS_NAME"
echo "==============================================================================="
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 could not be found. Please install Python 3.8+ on your system."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install dependencies if needed
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "[*] Checking and installing Python dependencies..."
    python3 -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet > /dev/null 2>&1 || true
fi

TARGET="${1:-$SCRIPT_DIR/base.apk}"

if [ ! -f "$TARGET" ]; then
    echo "[-] Target file not found: $TARGET"
    echo "Usage: ./run_ostadrespy.sh [path_to_any_file]"
    exit 1
fi

echo "[*] Analyzing target: $TARGET"
echo ""
python3 "$SCRIPT_DIR/ostadrespy.py" "$TARGET"

echo ""
echo "==============================================================================="
echo "  [+] Audit Finished! Report written to OstadRESpy_AUDIT_REPORT.md"
echo "==============================================================================="

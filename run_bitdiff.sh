#!/usr/bin/env bash
# ===============================================================================
#                [+] OstadBitDiff - Top 1% Binary Diffing Engine
#                   Created by Ostad Rezaul Karim (Director)
#                            Ostad Red Team Forge
#                       Email: ostadrezaulkarimofficial@gmail.com
# ===============================================================================

set -e

echo "==============================================================================="
echo "       [+] OstadBitDiff - Top 1% Binary Diffing & Trojan Hunter"
echo "            Author: Ostad Rezaul Karim | Ostad Red Team Forge"
echo "==============================================================================="
echo ""

if [ "$#" -lt 2 ]; then
    echo "Usage: ./run_bitdiff.sh <original_file> <modified_file>"
    echo "Example: ./run_bitdiff.sh clean.apk backdoored.apk"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/ostadbitdiff.py" "$1" "$2"

echo ""
echo "==============================================================================="
echo "  [+] Diff Completed! Report written to OstadBitDiff_REPORT.md"
echo "==============================================================================="

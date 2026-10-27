#!/data/data/com.termux/files/usr/bin/bash
# ===============================================================================
#                [+] OstadBitDiff - Android Phone Runner (Termux)
#                   Created by: Ostad Rezaul Karim (Director)
#                            Ostad Red Team Forge
#                       Email: ostadrezaulkarimofficial@gmail.com
# ===============================================================================

echo "==============================================================================="
echo "       [+] OstadBitDiff - Mobile Binary Differential Analyzer"
echo "            Author: Ostad Rezaul Karim | Ostad Red Team Forge"
echo "==============================================================================="
echo ""

if [ "$#" -lt 2 ]; then
    echo "Usage on Android: bash run_bitdiff_android.sh <original_apk> <modified_apk>"
    echo "Example: bash run_bitdiff_android.sh /sdcard/Download/clean.apk /sdcard/Download/modded.apk"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python "$SCRIPT_DIR/ostadbitdiff.py" "$1" "$2"

echo ""
echo "==============================================================================="
echo "  [+] Diff Completed! Report saved to OstadBitDiff_REPORT.md"
echo "==============================================================================="
